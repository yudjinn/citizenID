# Endpoints
## Authentication
headers:
- `auth_token`

- Endpoints marked with a 🔒 require a valid `auth_token` in  the header
- Endpoints marked with 🚫 can only be accessed from certain contexts, and should not be relied upon by applications.

## Misc
```
GET "/ping" : {} => "pong"
```

## Login
```
🚫 POST "/login/email" : {
	email: String,
	password: String,
} => {
	"auth_token": String,
	"refresh_token": String,
	"client_id": Uuid
}

🔒 POST  "/login/token" : {
	auth_token: String
} => {
	"grant_type": "refresh_token",
	"refresh_token": String,
	"client_id": Uuid
}

🔒 POST  "/login/token" : {
	auth_token: String
} => {
	"grant_type": "authorization_code",
	"authorization_code": String,
	"client_id": Uuid,
	"client_secret": String
}

🔒 POST  "/logout" : {
	"refresh_token": String
} => {}
```

##  Users
```
🔒 GET "/user" : {} => {
	🚫 "discord_sf": Option<String>,
	🚫 "email": Option<String>,
	"id": Uuid,
	"rsi_id": Option<String>,
	"sentinel": String,
	"status": [WaitingValidation,  Active, Inactive, Unknown]
}

🔒 GET "/user/apps" : {} => {
	[
		"client_id",
		"client_name",
		"scopes"
	]
}

🔒 PATCH "/user/update": {
	email: Option<String>,
	password: Option<String,
} => {
	"discord_sf": Option<String>,
	"email": Option<String>,
	"id": Uuid,
	"rsi_id": Option<String>,
	"sentinel": String,
	"status": [WaitingValidation,  Active, Inactive, Unknown]
}

🔒 DELETE "/user" : {} => {}

POST "/user" : {
	email: String,
	password: String,
} => {
	"discord_sf": Option<String>,
	"email": Option<String>,
	"id": Uuid,
	"rsi_id": Option<String>,
	"sentinel": String,
	"status": [WaitingValidation,  Active, Inactive, Unknown]
}
```

## Applications
```
🔒 GET "/applications/" : {} => {
	[
		"id": Uuid,
		"name": String,
		"callback_uris": List<String>,
		"status": [Active, Inactive,  Unknown],
	]
}

🔒 POST  "/applications" : {
	callback_uris: List<String>,
} => {
	"id": Uuid,
	"name": String,
	"user_id": Uuid,
	"secret": String,
	"callback_uris": List<String>
	"status": [Active, Inactive, Unknown]
}

🔒  DELETE "/applications/{client_id}" : {} => {}

🔒  PATCH "/applications/{client_id}" : {
		name: String,
		callback_uris: List<String>,
		status: [Active, Inactive,  Unknown],
} => {
		"id": Uuid,
		"name": String,
		"callback_uris": List<String>,
		"status": [Active, Inactive,  Unknown],
}

🔒  GET "/applications/{client_id}" : {} => {
		"id": Uuid,
		"name": String,
		"callback_uris": List<String>,
		"status": [Active, Inactive,  Unknown],
}
```

## OAuth
```
🔒 GET "/oauth?client_id&state&scopes&redirect_url" : {
	client_id: Uuid,
	state: code that is returned,
	scopes: '+' delimited list of scopes,
	redirect_uri: must exist in app's allowed uris
} => 
{
	// This is to review and show the user as acceptance
	"client_id": Uuid,
	"client_name": String,
	"user_id": Uuid,
	"redirect_uri": String,
	"scopes": Vec<String>,
	"state": String

🔒 POST "/oauth/authorize" : {
	client_id: Uuid,
	client_name: String,
	user_id: Uuid,
	redirect_uri: String,
	scopes: Vec<String>,
	state: String
} => 
{
	"code": String
}
```
