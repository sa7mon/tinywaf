package tinywaf

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

var bans map[string]time.Time

func init() {
	caddy.RegisterModule(TinyWAF{})
	httpcaddyfile.RegisterHandlerDirective("tinywaf", parseCaddyfile)
	bans = make(map[string]time.Time)
}

type TinyWAF struct {
	BadURIs        []string `json:"bad_uris,omitempty"`
	BanMinutes     int      `json:"ban_minutes,omitempty"`
	badURIPatterns []*regexp.Regexp
	logger         *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (TinyWAF) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.tinywaf",
		New: func() caddy.Module { return new(TinyWAF) },
	}
}

// Provision implements caddy.Provisioner.
func (m *TinyWAF) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	for _, pattern := range m.BadURIs {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		m.badURIPatterns = append(m.badURIPatterns, re)
	}
	m.logger.Info(fmt.Sprintf("%v URI patterns loaded", len(m.badURIPatterns)))
	m.logger.Info(fmt.Sprintf("ban_minutes set to %v", m.BanMinutes))
	return nil
}

// Validate implements caddy.Validator.
func (m *TinyWAF) Validate() error {
	if m.BanMinutes <= 0 {
		return fmt.Errorf("ban_minutes must be > 0")
	}
	return nil
}

func respondWithBlock(w http.ResponseWriter) error {
	w.WriteHeader(http.StatusForbidden)
	_, err := w.Write([]byte("be gone, bot"))
	return err
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m TinyWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := r.Header.Get("Cf-Connecting-Ip")
	m.logger.Info(fmt.Sprintf("bans: %v", bans))

	// are you already banned?
	until, banned := bans[ip]
	if banned {
		if time.Now().Before(until) {
			m.logger.Info(fmt.Sprintf("banned IP %s tried to request %s. %.0f minutes remaining on ban", ip, r.RequestURI, time.Until(until).Minutes()))
			return respondWithBlock(w)
		}
		delete(bans, ip) // the ban has been lifted
	}

	// if not, should you be?
	for _, pattern := range m.badURIPatterns {
		if pattern.MatchString(r.RequestURI) {
			m.logger.Info(fmt.Sprintf("ip %s requested bad URI '%s'. Blocking IP", ip, r.RequestURI))
			bans[ip] = time.Now().Add(time.Duration(m.BanMinutes) * time.Minute)
			return respondWithBlock(w)
		}
	}

	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *TinyWAF) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			key := d.Val()
			switch key {
			case "ban_minutes":
				if !d.NextArg() {
					return d.ArgErr()
				}
				minutes, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.ArgErr()
				}
				m.BanMinutes = minutes
			case "bad_uris":
				if d.NextArg() { // arg after bad_uris instead of a brace
					return d.ArgErr()
				}
				if !d.NextBlock(0) { // expected to find the opening of a block, but found something else
					return d.ArgErr()
				}

				for d.NextLine() {
					arg := d.Val()
					if arg == "}" {
						break
					}
					m.BadURIs = append(m.BadURIs, arg)
				}
			case "}", "{":
			default:
			}
		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m TinyWAF
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*TinyWAF)(nil)
	_ caddy.Validator             = (*TinyWAF)(nil)
	_ caddyhttp.MiddlewareHandler = (*TinyWAF)(nil)
	_ caddyfile.Unmarshaler       = (*TinyWAF)(nil)
)
