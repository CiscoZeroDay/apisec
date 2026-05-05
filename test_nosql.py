import requests, urllib3
urllib3.disable_warnings()

r1 = requests.post('http://localhost:8888/identity/api/auth/login',
    json={'email': {'\': ''}, 'password': {'\': ''}})
print('TRUE :', r1.status_code, r1.text[:300])

r2 = requests.post('http://localhost:8888/identity/api/auth/login',
    json={'email': {'\': ''}, 'password': {'\': ''}})
print('FALSE:', r2.status_code, r2.text[:300])

r3 = requests.post('http://localhost:8888/identity/api/auth/login',
    json={'email': 'wrong@test.com', 'password': 'wrongpass'})
print('WRONG:', r3.status_code, r3.text[:300])
