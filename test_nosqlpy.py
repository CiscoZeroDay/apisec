import requests, urllib3
urllib3.disable_warnings()

true_payload  = {"email": {"$gt": ""}, "password": {"$gt": ""}}
false_payload = {"email": {"$lt": ""}, "password": {"$lt": ""}}
wrong_payload = {"email": "wrong@test.com", "password": "wrongpass"}

r1 = requests.post("http://localhost:8888/identity/api/auth/login", json=true_payload)
print("TRUE :", r1.status_code, r1.text[:300])

r2 = requests.post("http://localhost:8888/identity/api/auth/login", json=false_payload)
print("FALSE:", r2.status_code, r2.text[:300])

r3 = requests.post("http://localhost:8888/identity/api/auth/login", json=wrong_payload)
print("WRONG:", r3.status_code, r3.text[:300])