import http.client

conn = http.client.HTTPConnection("localhost:3000")

payload = "grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Fcitizen-id-callback&client_id=a1245884-a9b6-47d1-b5a9-90172f3ef7df&client_secret=EXAMPLE_CLIENT_SECRET&code=EXAMPLE_AUTH_CODE"

headers = { 'Content-Type': "application/x-www-form-urlencoded" }

conn.request("POST", "/login/token", payload, headers)

res = conn.getresponse()
data = res.read()

print(data.decode("utf-8"))
