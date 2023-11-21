
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

🔒 POST "/user/delete" : {} => {}

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
		callback_uris: List<String>,
		status: [Active, Inactive,  Unknown],
	]
}

🔒 POST  "/applications/new" : {
	callback_uris: List<String>,
} => {
	id: Uuid,
	user_id: Uuid,
	secret: String,
	callback_uris: List<String>
	status: [Active, Inactive, Unknown]
}

🔒  POST "/applications/delete/{app_id}" : {} => {}
```
