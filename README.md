# GO-OAUTH2

OAuth 2.0 server library for Golang.

## Install

## Get Start

### generate rsa key

go-oauth2 use rs256 for generate jwt token,it need rsa pair key

use bellow command in the openssl console
```openssl
//generate private key
genrsa -out rsa_auth.key 1024
//use pkcs8
pkcs8 -topk8 -in rsa_auth.key -out rsa_auth_pkcs8.pem -outform pem -nocrypt
//generate public key
rsa -in rsa_auth.key -pubout -out rsa_pub.pem -outform pem
```

### generate encryption key

the internal payload data use aes encrypt,so you need generate a 32 length string

## test

if you change repository interface,rebuild the mock of repository interface 
 ```
mockgen -source repository_interface.go -destination=mocks/mock_repository.go
```