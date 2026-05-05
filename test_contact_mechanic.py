import requests, urllib3, json
urllib3.disable_warnings()

token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjaXNjb0BnbWFpbC5jb20iLCJpYXQiOjE3Nzc5NzU0NzcsImV4cCI6MTc3ODU4MDI3Nywicm9sZSI6InVzZXIifQ.qXmhFNCNuef9O5RnXOn8X_Ep39hykpGQOxMOOt-PSfUXtBvmQn24CikMdnQbEhrpBxy8tRVRdnp32FGSiZsN7LNn1LWH3xqtdf9LRNjEPjFkTumVIScSHZWK_Pc3XHSX1W5WCcQYmnALgW3-azHkP0UhnK1crnZeXQYj1eIsdgASZ68gC6hWV1b504TmFedub7oU_a0olJhL8ckdWB47InLjkwOMba8a8VxsvEW1ItYL8NcczXzkpKoNv4-pZhBBj2mCkmWg70_LR6B0CzWW3gM7Ew7un_nByXz6Vjgh7UqeGG0_yAK_z5fDFKXe-AohILEsqxEyh9iBZY-avSNCsA"
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
url = "http://localhost:8888/workshop/api/merchant/contact_mechanic"

# GET
r1 = requests.get(url, headers=headers)
print("GET:", r1.status_code, r1.text[:300])

# POST empty
r2 = requests.post(url, json={}, headers=headers)
print("POST empty:", r2.status_code, r2.text[:300])

# POST with known crAPI body
body = {
    "mechanic_code": "TRAC_JME",
    "problem_details": "test",
    "vin": "test",
    "mechanic_api": "http://mechanic-app:8080/",
    "repeat_request": False,
    "number_of_repeats": 1
}
r3 = requests.post(url, json=body, headers=headers)
print("POST full:", r3.status_code, r3.text[:500])