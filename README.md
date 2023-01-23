# Honeyaml
[![CI](https://github.com/mmta/honeyaml/actions/workflows/publish.yml/badge.svg)](https://github.com/mmta/honeyaml/actions/workflows/publish.yml)

This is an API server honeypot whose endpoints and responses are all configurable through a YAML file, supports builtin JWT-based HTTP bearer/token authentication, and logs all accesses into a file in JSON lines format.

## Example

With this yaml file:

```yaml
- path: /auth
  path_type: authenticator
  method: POST
  authorization: jwt
  auth_config:
    issuer: Org
    subject: MyApp
    audience: MyApp
  accounts:
    - username: user
      password: passwd1
    - username: admin
      password: admpasswd
      realm: asgard
- path: /end-point1
  path_type: rest
  method: GET
  auth_required: true
  return_code: 200
  return_text: |
    {
      "doc_id": 1,
      "field" : "hello"
    }
```
The "user" will get the following experience:
```shell
# exploring available paths
$ curl 'localhost:8080/foo' -sSf
curl: (22) The requested URL returned error: 401 Unauthorized
$ curl 'localhost:8080/foo' -H 'Authorization: Bearer bar' -sSf
curl: (22) The requested URL returned error: 404 Not Found
$ curl 'localhost:8080/auth' -H 'Authorization: Bearer bar' -XPOST -sSf 
curl: (22) The requested URL returned error: 401 Unauthorized

# assisted brute-force
$ curl 'localhost:8080/auth' -XPOST -d'{}'
incorrect/missing parameter ["password", "realm", "username"]

# the breakthrough
curl 'localhost:8080/auth' -s -XPOST -d'{ "username": "admin", "password": "admpasswd", "realm": "asgard" }'
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzQ0NzIxMDEsImV4cCI6MTY3NDQ3OTMwMSwibmJmIjoxNjc0NDcyMTAxLCJpc3MiOiJPcmciLCJzdWIiOiJNeUFwcCIsImF1ZCI6Ik15QXBwIn0.YcQbrRlIgMhZXhz_W9PgiA9pg2mslEGDDObdQtJsevI

# an actual token usable for 2 hours
$ export TOKEN=$(curl 'localhost:8080/auth' -s -XPOST -d'{ "username": "admin", "password": "admpasswd", "realm": "asgard" }')
$ jq -R 'split(".") | .[0],.[1] | @base64d | fromjson' <<< $(echo "${TOKEN}")
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "iat": 1674472119,
  "exp": 1674479319,
  "nbf": 1674472119,
  "iss": "Org",
  "sub": "MyApp",
  "aud": "MyApp"
}

# capturing the ultimate prize
$ curl 'localhost:8080/end-point1?sploit=%3Cscript%3Ealert%28%27test%27%29%3C%2Fscript%3E' -H "Authorization: Bearer $TOKEN"
{
  "doc_id": 1,
  "field" : "hello"
}

```
In return we'll get these on the log file:

```json lines
{"timestamp":"2023-01-23T11:07:57.527891Z","level":"WARN","fields":{"remote_ip":"127.0.0.1","path":"/foo","method":"GET","query_string":"","body":"","status_code":404,"headers":"host=localhost:8080,user-agent=curl/7.68.0,accept=*/*,authorization=Bearer bar,"},"target":"honeyaml::access-log"}

{"timestamp":"2023-01-23T11:08:12.993052Z","level":"WARN","fields":{"remote_ip":"127.0.0.1","path":"/auth","method":"POST","query_string":"","body":"{}","status_code":401,"headers":"content-type=application/x-www-form-urlencoded,accept=*/*,host=localhost:8080,user-agent=curl/7.68.0,content-length=2,"},"target":"honeyaml::access-log"}

{"timestamp":"2023-01-23T11:08:21.528897Z","level":"WARN","fields":{"remote_ip":"127.0.0.1","path":"/auth","method":"POST","query_string":"","body":"{ \"username\": \"admin\", \"password\": \"admpasswd\", \"realm\": \"asgard\" }","status_code":200,"headers":"content-length=67,host=localhost:8080,user-agent=curl/7.68.0,content-type=application/x-www-form-urlencoded,accept=*/*,"},"target":"honeyaml::access-log"}

{"timestamp":"2023-01-23T11:08:39.606198Z","level":"WARN","fields":{"remote_ip":"127.0.0.1","path":"/auth","method":"POST","query_string":"","body":"{ \"username\": \"admin\", \"password\": \"admpasswd\", \"realm\": \"asgard\" }","status_code":200,"headers":"host=localhost:8080,content-length=67,user-agent=curl/7.68.0,accept=*/*,content-type=application/x-www-form-urlencoded,"},"target":"honeyaml::access-log"}

{"timestamp":"2023-01-23T11:09:02.113894Z","level":"WARN","fields":{"remote_ip":"127.0.0.1","path":"/end-point1","method":"GET","query_string":"sploit=%3Cscript%3Ealert%28%27test%27%29%3C%2Fscript%3E","body":"","status_code":200,"headers":"user-agent=curl/7.68.0,host=localhost:8080,accept=*/*,authorization=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzQ0NzIxMTksImV4cCI6MTY3NDQ3OTMxOSwibmJmIjoxNjc0NDcyMTE5LCJpc3MiOiJPcmciLCJzdWIiOiJNeUFwcCIsImF1ZCI6Ik15QXBwIn0.tYMgW-Kvvlf7M0M_T0OYtuW12YmLP7cHHLgVrctrPqA,"},"target":"honeyaml::access-log"}

```
Which should be easy to consume by typical security monitoring infrastructure.

## The YAML config file

There's no limit on how many paths can be defined. Each path can have its own return code, return text, authentication required flag, and HTTP method. Refer to [api.yaml](./api.yml) file for examples.

## Install & usage

Clone this repo and build the binary (requires rust development environment):

```shell
$ cargo build -r
$ ./target/release/honeyaml --help

```
Or use the prebuilt docker image:

```shell
$ mkdir -p logs && chmod 770 logs && sudo chown 10001 logs
$ docker run --rm --name honeyaml -v $(pwd)/logs:/honeyaml/logs mmta/honeyaml
```
To test it from another terminal session:
```shell
$ export target=$(docker container inspect honeyaml | jq -r ".[].NetworkSettings.Networks.bridge.IPAddress")

$ curl "${target}:8080/auth" -XPOST -d'{}'
incorrect/missing parameter ["password", "realm", "username"]
```