# tinywaf

A simple (naive) web application firewall for [Caddy](https://caddyserver.com) to ban IPs based on requested URI patterns.


* **tested?** a little
* **secure?** nahh
* **memory leak**? big time
* **simple?** oh yeah

## Usage

Refer to `Caddyfile` for example config

```
tinywaf {
    bad_uris {
        ^/wp-admin/.+$
        ^/login.php
        .*/wp-(includes|admin|content)/.*
    }
    ban_minutes 120
}
```

IP addresses making requests to `bad_uris` will be banned for `ban_minutes` and will receive a `403 Forbidden`. Module is designed to be used with Cloudflare and will assume the `Cf-Connecting-Ip` header is present - change `ServeHTTP` logic if you don't want this.