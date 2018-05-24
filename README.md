# GO-OAUTH2

OAuth 2.0 server library for Golang.

 ## test

if you change repository interface,rebuild the mock of repository interface 
 ```
mockgen -source repository_interface.go -destination=mocks/mock_repository.go
```