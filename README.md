# jwtgen

A simple program that generates JWTs, specifically ones that look like Apple Signin JWTs.

To install:

```bash
go get github.com/coleaeason/jwtgen
```

To use it:
```bash
$ jwtgen --help
Usage of jwtgen
Example usages:
  Generate a default, valid token:
    jwtgen
  Generate a default, valid token, and pretty-print debug information:
    jwtgen --debug -pp
  Generate an expired token for cole@test.com:
    jwtgen --expired --email=cole@test.com

Options: 
  -aud string
        Audience for token (default "com.fake.fake.AppleSignIn")
  -debug
        Print some debug information
  -email string
        Email of user (default "test@example.com")
  -error string
        Specfiy an error message in this token
  -expired
        Should the token be expired, defaults to false
  -iss string
        Issuer for token (default "https://appleid.apple.com")
  -pp
        Pretty print JSON, defaults to false.
  -sub string
        Subject of the token (default "Test User")
```
