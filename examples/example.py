from oauthlib.oauth2 import WebApplicationClient
import requests
import json

client_id = 'b10cadbb-f041-48e1-902d-e4a356ded54d'
secret = '00000000-0000-0000-0000-000000000000'
auth_token = "EXAMPLE_JWT_TOKEN"
client = WebApplicationClient(client_id)
# review = json.json({
#     "app_id": client_id,
#     "app_name": "Python Example",
#     "user_id": Uuid,
#     "scopes": Scopes,
#     "redirect_uri": String,
#     "state": String,
# })


headers={
        "Auth_token": auth_token,
        "Origin": "https://staging.citizen-id.space",
         }
preflight_url = "https://api-staging.citizen-id.space/oauth?app_id=b10cadbb-f041-48e1-902d-e4a356ded54d&state=test&scopes=get_user"
preflight_response = requests.get(preflight_url,headers=headers)
print(preflight_response.text)
payload = json.loads(preflight_response.text).get("payload")
payload.pop("app_name")
payload.pop("user_id")

authorization_url = 'https://api-staging.citizen-id.space/oauth?app_id=b10cadbb-f041-48e1-902d-e4a356ded54d&state=test&scopes=get_user'
init_response = requests.get(authorization_url, headers=headers)
auth_payload = json.loads(init_response.text).get("payload")

approve_url = 'https://api-staging.citizen-id.space/oauth/authorize'
post_headers = headers.update({'Content-Type': 'application/json'})
approve_response = requests.post(approve_url, headers=headers, json=auth_payload)

from urllib.parse import unquote
import base64
token = unquote(approve_response.url.split("token=")[1])
token_dec = base64.b64decode(token)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

cipher = Cipher(algorithms.AES(secret.encode('utf-8')[:32]), modes.ECB())
decryptor = cipher.decryptor()
decrypted_data = decryptor.update(token_dec) + decryptor.finalize()

unpadder = padding.PKCS7(128).unpadder()
plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

token_url = 'https://api-staging.citizen-id.space/login/token'
token_payload = json.loads(f'"refresh_token": "{plaintext}", "app_id": "{client_id}"')
response = requests.post(token_url, data=token_payload)
z
