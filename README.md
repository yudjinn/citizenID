[![Corvus Backend](https://github.com/sc-corvus/citizenID/actions/workflows/rust.yml/badge.svg)](https://github.com/sc-corvus/citizenID/actions/workflows/rust.yml)

## Configuration

Configuration is supplied via environment variables. Copy the example file and
fill in your own values:

```
cp .env.example .env
```

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `SECRET_KEY` | prod | insecure built-in | HMAC key for signing/verifying tokens. Set a long random value in any real deployment. |
| `SALT_KEY` | prod | insecure built-in | Salt key used in password/token hashing. |
| `MASTER_CLIENT_ID` | prod | built-in dev UUID | UUID of the first-party OAuth client that owns the user API. |
| `CORS_ORIGINS` | no | (none) | Space-separated list of allowed origins. |
| `CORS_ALLOW_CREDENTIALS` | no | `false` | Send `Access-Control-Allow-Credentials: true`. |
| `AWS_REGION` / `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | no | AWS SDK chain | DynamoDB credentials. Can also come from an AWS profile (`dev` for the default build, `local` for the `tempdb` feature). |
| `AWS_ENDPOINT_URL_DYNAMODB` | local only | (none) | Point the SDK at DynamoDB Local, e.g. `http://localhost:8000`. |
| `RUST_LOG` | no | `info` | Log filter. |

See [`.env.example`](.env.example) for the full annotated list.

## Dev
For local db:

`docker-compose -f ./tools/dynamodb-local.yml up -d`

View the db via dui using the npm package `dynamodb-admin`: `npm -i dynamodb-admin`

Also need a aws config in `~/.aws/config`:
```
[profile localstack]
region = us-east-1
aws_access_key_id = AKIDLOCALSTACK
aws_secret_access_key = localstacksecret
```

Test User:
test@email.co
password3

[Product mgmt](https://app.plane.so/vestra/projects/7838ebfd-b388-47dd-b162-72c7aa53d41c/issues)
