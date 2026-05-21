import requests, urllib3
urllib3.disable_warnings()

token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjaXNjb0BnbWFpbC5jb20iLCJpYXQiOjE3Nzg4NDQ5ODcsImV4cCI6MTc3OTQ0OTc4Nywicm9sZSI6InVzZXIifQ.rfgO6BqL9QYw6StW1S9AaUskMb52OypYSfhejWBcyKSNDN7aKAN1zzNImnqCOlmdSl-qS7emUVWeXIMO9ZCE351BvH_K3W7AW-9KnJOukW5yRGW-9xjialrAoMo50F1kOHVMI_C9xTDy5_qm8kXqLRHdgMwJKawgNdf4HLzfxl4Q84tF0wqyR9zvyDQ3nIprmSH_nD9iLnZuox81uA0Yujv8Fr7oWv15gjHPHHmI6ZlC1M_1n_tWnppuJvt-oOFFCAhbC229c5IakV1LphYXbuMhmG3-KYIQXNeKcrLOEsJkbynQQTtiQfOrk2DCPiR0zJemPHKwnzocJD2bks5bMg"
headers = {"Authorization": f"Bearer {token}"}
base = "http://localhost:8888"

# Step 1 — get all orders to find real IDs
r = requests.get(f"{base}/workshop/api/shop/orders/all", headers=headers)
print("ALL ORDERS:", r.status_code, r.text[:300])
print()

# Step 2 — test a few IDs directly
for i in range(1, 10):
    r = requests.get(f"{base}/workshop/api/shop/orders/{i}", headers=headers)
    print(f"  /orders/{i} → {r.status_code} | {r.text[:100]}")