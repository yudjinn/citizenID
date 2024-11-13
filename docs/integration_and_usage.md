# Integration and Usage

## Setup
The end application that would like to use CitizenID for auth must first be setup. To do so:
- Application owner must make an account on `citizen-id.space` and then navigate to "Create Application"
- Input a name, redirect URI's you'd like to be able to use (this is a whitelist), and click "Create"
- Make note of the ID and Secret; the ID can always be retreive later but the Secret can never be read again.
Note: If you forget (or need to rotate your secret for some other reason), the "Regenerate Secret" button will do so.

## Process Flow
The integrating application (referred to as "App") has a specific workflow setup with the auth service (referred to as "Provider").
App will provide some kind of "Login with CitizenID!" button. This button will do the following:
1. Route to `citizen-id.space/oauth` with query parameters as follows:
```
     app_id
     redirect_uri: Optional, but recommended
     state: Optional
     scopes
```
- Scopes here are a "+" separated list of [scopes](#scopes)
2. The end user will be required to login first, but after approval, a redirect will happen to the given `redirect_uri` with a `code`
3. This code acts as a one-time-use authority to enable initial access of an account. To use it, make a POST request to `citizen-id.space/login/token` with json body of:
```json
{
    "grant_type": "authorization_code",
    "authorization_code": "code from previous step",
    "app_id": "app ID from setup",
    "app_secret": "secret from setup"
}
```
- This will return an `auth_token` and `refresh_token`. The `auth_token` will have the scopes specified during the oauth process, and the `refresh_token` can be used to get a new token set on expiry.
4. To get a new token set, a POST request to `citizen-id.space/login/token` with the body:
```json
{
    "grant_type": "refresh_token",
    "refresh_token": "refresh_token for user",
    "app_id": "app ID from setup"
}
```
- This will return a new keyset and usage can continue

### Scopes
- "get_user"
- "get_discord"

## Usage
The `auth_token` from the [Setup](#setup) section can be used to hit the API as if you were the user.
The API endpoints are detailed more in [endpoints.md](/docs/endpoints.md), but the key usage is:
API URI: `api.citizen-id.space`
Headers: `auth_token`
