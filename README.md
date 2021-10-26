# go-avauth-oauth2

This is a oauth2 provider that use the aventer backend systems to authenticate. To be honest, it makes no sense for other peoples to use it, but I think it's a interesting starting point for the own oauth2 project. So, feel free and have a look around.

## How to use

This OAuth provider need the following information as environment variable.

```bash
export AUTH_SERVER=https://<AUTH SERVER>
export CLIENTDOMAIN=
export CLIENTID=
export CLIENTSECRET=
export GROUP=<USER GROUP>
export IDENTIFIER=
export JWT_SIGNKEY=<A VERY STRONG AND LONG PHRASE>
export LOGLEVEL=<debug|warn|info>
export REDIS_SERVER=<REDIS_SERVER>:6379

go run main.go

```


