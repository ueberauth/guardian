# Tokens

Guardian uses the concept of a _token_ as a currency of authentication credentials.

Tokens can be anything that has the following properties:

* tamper proof (signed/encrypted verifyable by the application)
* include a payload (claims)

Claims should be a map using string keys.

JWT tokens (the default) fit these requirements and are widely supported in most languages using either hashed or cert based signing algorithms. However this is only one option. You can provide other behaviours like revocation, db tracking or another standard token type.

Tokens can be provided by any means, they can be put into HTTP request headers, cookies, sessions; really as long as you can get your token to your application you can verify it and use it.

Configuration of your token has two parts:

1. Config - options are provided by the token module that you're using
2. Implementation module - The module for
