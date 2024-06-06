
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
	app_id: Uuid
}

🔒 POST  "/login/token" : {
	auth_token: String
} => {
	auth_token: String,
	refresh_token: String,
	app_id: Uuid
}

🔒 POST  "/logout" : {
	"refresh_token": String
} => {}
```

##  Users
```
🔒 GET "/user" : {} => {
	discord_sf: Option<String>,
	email: Option<String>,
	id: Uuid,
	rsi_id: Option<String>,
	sentinel: String,
	status: [WaitingValidation,  Active, Inactive, Unknown]
}

🔒 GET "/user/apps" : {} => {
	[
		"app_id",
		"app_name",
		"scopes"
	]
}

🔒 PATCH "/user/update": {
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

🔒 DELETE "/user" : {} => {}

POST "/user" : {
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

🔒 POST  "/applications" : {
	callback_uris: List<String>,
} => {
	id: Uuid,
	name: String,
	user_id: Uuid,
	secret: String,
	callback_uris: List<String>
	status: [Active, Inactive, Unknown]
}

🔒  DELETE "/applications/{app_id}" : {} => {}

🔒  PATCH "/applications/{app_id}" : {
		name: String,
		callback_uris: List<String>,
		status: [Active, Inactive,  Unknown],
} => {
		id: Uuid,
		name: String,
		callback_uris: List<String>,
		status: [Active, Inactive,  Unknown],
}

🔒  GET "/applications/{app_id}" : {} => {
		id: Uuid,
		name: String,
		callback_uris: List<String>,
		status: [Active, Inactive,  Unknown],
}
```

## OAuth
```
🔒 GET "/oauth/preflight?app_id&state&scopes&redirect_url" : {
	app_id: Uuid,
	state: code that is returned,
	scopes: '+' delimited list of scopes,
	redirect_uri: must exist in app's allowed uris
} => 
{
  Preflight check of vars that returns json message for what was invalid.
}

🔒 GET "/oauth?app_id&state&scopes&redirect_url" : {
	app_id: Uuid,
	state: code that is returned,
	scopes: '+' delimited list of scopes,
	redirect_uri: must exist in app's allowed uris
} => 
{
	// This is to review and show the user as acceptance
	app_id: Uuid,
	app_name: String,
	user_id: Uuid,
	redirect_uri: String,
	scopes: Vec<String>,
	state: String

🔒 POST "/oauth/authorize" : {
	app_id: Uuid,
	app_name: String,
	user_id: Uuid,
	redirect_uri: String,
	scopes: Vec<String>,
	state: String
} => 
{
	refresh_token: Uuid
}
