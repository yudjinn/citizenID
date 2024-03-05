[![Corvus Backend](https://github.com/sc-corvus/citizenID/actions/workflows/rust.yml/badge.svg)](https://github.com/sc-corvus/citizenID/actions/workflows/rust.yml)

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

## TODO:
- [ ] Refactor codebase -- use something like [this](https://www.youtube.com/watch?v=zUxF0kvydJs)
