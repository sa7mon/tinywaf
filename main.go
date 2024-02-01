package tinywaf

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
)

var blockedIPs []string

func init() {
	caddy.RegisterModule(TinyWAF{})
	httpcaddyfile.RegisterHandlerDirective("tinywaf", parseCaddyfile)
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

	//badURIPatterns := []string{`^/wp-admin/.+`}

	// range m.badURIPatterns
	for _, pattern := range m.BadURIs {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		m.badURIPatterns = append(m.badURIPatterns, re)
	}
	m.logger.Debug(fmt.Sprintf("%v URI patterns loaded", len(m.badURIPatterns)))
	return nil
}

// Validate implements caddy.Validator.
func (m *TinyWAF) Validate() error {
	//if m.w == nil {
	//	return fmt.Errorf("no writer")
	//}
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
	m.logger.Info(fmt.Sprintf("blocked IPs: %v", blockedIPs))

	if slices.Contains(blockedIPs, ip) {
		return respondWithBlock(w)
	}

	for _, pattern := range m.badURIPatterns {
		if pattern.MatchString(r.RequestURI) {
			m.logger.Info(fmt.Sprintf("ip %s requested bad URI '%s'. Blocking IP", ip, r.RequestURI))
			blockedIPs = append(blockedIPs, ip)
			return respondWithBlock(w)
		}
	}

	return next.ServeHTTP(w, r)
}

func tempLog(f *os.File, s string) {
	_, err := f.WriteString(s + "\n")
	if err != nil {
		log.Fatal(err)
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *TinyWAF) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	f, ferr := os.Create("temp.log")
	if ferr != nil {
		return ferr
	}
	// remember to close the file
	defer f.Close()

	tempLog(f, "hello from UnmarshalCaddyfile")
	for d.Next() {
		for d.NextBlock(0) {
			key := d.Val()
			switch key {
			case "ban_minutes":
				if !d.NextArg() {
					return d.ArgErr()
				}
				tempLog(f, "found ban_minutes key")
				minutes, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.ArgErr()
				}
				m.BanMinutes = minutes
				tempLog(f, fmt.Sprintf("setting ban_minutes to %v", minutes))
			case "bad_uris":
				tempLog(f, "found bad_uris key")
				if d.NextArg() { // arg after bad_uris instead of a brace
					return d.ArgErr()
				}
				if !d.NextBlock(0) {
					// expected to find the opening of a block, but found something else
					return d.ArgErr()
				}
				//tempLog(f, fmt.Sprintf("bad_uris val: %s", d.Val()))

				for d.NextLine() {
					arg := d.Val()
					if arg == "}" {
						//continue
						break
					}
					tempLog(f, fmt.Sprintf("bad_uris arg: %s", arg))
				}
				//if !d.Args(&value) {
				//	// not enough args
				//	return d.ArgErr()
				//}
				//
				//if d.NextArg() {
				//	// too many args
				//	return d.ArgErr()
				//}
			case "}", "{":

			default:
				tempLog(f, fmt.Sprintf("found other key: %s", key))
			}
		}
		//tempLog(f, fmt.Sprintf("key: %s", key))
	}
	//for d.Next() { // consume directive name
	//	var value string
	//	m.logger.Info("directive: " + d.Val())
	//	if !d.Args(&value) {
	//		// not enough args
	//		return d.ArgErr()
	//	}
	//	m.logger.Info("value: " + value)
	//}

	//// require an argument
	//if !d.NextArg() {
	//	return d.ArgErr()
	//}

	//d.ValRaw()
	// store the argument
	//uris := make([]string, 0)
	//m.BadURIs = d.Val()
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
