from oauthlib.oauth2 import WebApplicationClient
import requests
import json

client_id = 'b10cadbb-f041-48e1-902d-e4a356ded54d'
secret = '00000000-0000-0000-0000-000000000000'
auth_token = "EXAMPLE_JWT_TOKEN"
client = WebApplicationClient(client_id)
# review = json.json({
#     "client_id": client_id,
#     "client_name": "Python Example",
#     "user_id": Uuid,
#     "scopes": Scopes,
#     "redirect_uri": String,
#     "state": String,
# })


headers={
        "access_token": auth_token,
        "Origin": "https://staging.citizen-id.space",
         }
preflight_url = "https://api-staging.citizen-id.space/oauth?client_id=b10cadbb-f041-48e1-902d-e4a356ded54d&state=test&scopes=get_user"
preflight_response = requests.get(preflight_url,headers=headers)
print(preflight_response.text)
payload = json.loads(preflight_response.text).get("payload")
payload.pop("client_name")
payload.pop("user_id")

authorization_url = 'https://api-staging.citizen-id.space/oauth?client_id=b10cadbb-f041-48e1-902d-e4a356ded54d&state=test&scopes=get_user'
init_response = requests.get(authorization_url, headers=headers)
auth_payload = json.loads(init_response.text).get("payload")

approve_url = 'https://api-staging.citizen-id.space/oauth/authorize'
post_headers = headers.update({'Content-Type': 'application/json'})
approve_response = requests.post(approve_url, headers=headers, json=auth_payload)

# TODO:
# grab code from payload
# use code, client_id, and client_secret to get login token
login_url = 'https://api-staging.citizen-id.space/login/oauth'

