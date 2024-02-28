
## Authentication
headers:
- `auth_token`
- `refresh_token`

Endpoints marked with a 🔒 require a valid `auth_token` in  the header

## Misc
```
GET "/ping" : {} => "pong"
```

## Login
```
POST "/login/email" : {
	email: String,
	password: String,
} => {
	auth_token: String,
	refresh_token: String,
}

🔒 POST  "/login/token" : {
	auth_token: String
} => {
	auth_token: String,
	refresh_token: String,
}

🔒 POST  "/logout" : {} => {}
```

##  Users
```
🔒 GET "/user/" : {} => {
	discord_sf: Option<String>,
	email: Option<String>,
	id: Uuid,
	rsi_id: Option<String>,
	sentinel: String,
	status: [WaitingValidation,  Active, Inactive, Unknown]
}

🔒 PUT "/user/update": {
	email: Option<String>,
	password: Option<String,
} => {
	discord_sf: Option<String>,
	email: Option<String>,
	id: Uuid,
	rsi_id: Option<String>,
	sentinel: String,
	status: [WaitingValidation,  Active, Inactive, Unknown]
}

🔒 DELETE "/user/delete" : {} => {}

POST "/user/new" : {
	email: String,
	password: String,
} => {
	discord_sf: Option<String>,
	email: Option<String>,
	id: Uuid,
	rsi_id: Option<String>,
	sentinel: String,
	status: [WaitingValidation,  Active, Inactive, Unknown]
}
```

## Applications
```
🔒 GET "/applications/" : {} => {
	[
		id: Uuid,
		name: String,
		callback_uris: List<String>,
		status: [Active, Inactive,  Unknown],
	]
}

🔒 POST  "/applications/new" : {
	callback_uris: List<String>,
} => {
	id: Uuid,
	name: String,
	user_id: Uuid,
	secret: String,
	callback_uris: List<String>
	status: [Active, Inactive, Unknown]
}

🔒  POST "/applications/delete/{app_id}" : {} => {}

🔒  PUT "/applications/update/{app_id}" : {
		name: String,
		callback_uris: List<String>,
		status: [Active, Inactive,  Unknown],
} => {
		id: Uuid,
		name: String,
		callback_uris: List<String>,
		status: [Active, Inactive,  Unknown],
}
```

## OAuth
```
🔒 GET "/oauth" : {
	corvus_key: application's id,
	corvus_secret: application's secret,
	corvus_request: specific uri to redirect to, if it's in the list of callbacks
		->  otherwise, use first callback,
	TODO: scopes to enable
} => 
THIS SHOULD FIRST PROMPT THE USER FOR CONSENT(not yet implemented) =>
REDIRECT to redirect uri chosen (or first in list for application)
{
	corvus-auth: payload containing corvus user-id and rsi_id tied to account
		-> encoded using application's secret
}

TODO: NOT IMPLEMENTED YET:
🔒 POST "/oauth" : {
	corvus_key: application's id,
	corvus_auth: encoded key from earlier,
	} => {
		corvus_token: auth token for access to user details, based on scope
	}
### This token expires after a set TTL, and the end application will have to re-prompt for access
```

