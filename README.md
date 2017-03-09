# Ride: Web Security (JWT)

This module implements Json Web Token in the security layer of a Ride web application.

When authenticated using another authentication system, like username/password or OAuth, you can obtain your token through _/api/v1/jwt_.
To use this for API calls, set the obtained token in the _Authorization_ header for any subsequent request like:

```
Authorization: Bearer <token>
```

## Parameters

* __security.jwt.algorithm__: Algorithm of the Json Web Token (defaults to HS256)
* __security.jwt.exp__: Timestamp when the token is expired or an offset in seconds with the current time by prepending a + (optional)
* __security.jwt.audience__: Audience of the Json Web Token (optional)
* __security.jwt.nbf__: Before this timestamp the token is invalid, can also be an offset in seconds with the current time by prepending a + (optional)
* __security.jwt.issuer__: Issuer of the Json Web Token (optional)
* __security.jwt.subject__: Subject of the Json Web Token (optional)

## Related Modules 

- [ride/app](https://github.com/all-ride/ride-app)
- [ride/lib-security](https://github.com/all-ride/ride-lib-security)
- [ride/web](https://github.com/all-ride/ride-web)
- [ride/web-security](https://github.com/all-ride/ride-web-security)

## Installation

You can use [Composer](http://getcomposer.org) to install this application.

```
composer require ride/web-security-jwt
```
