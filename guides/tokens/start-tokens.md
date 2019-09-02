# Tokens

Guardian uses the concept of a _token_ as a currency of authentication credentials.

Tokens can be anything that has the following properties:

* tamper proof (signed/encrypted verifiable by the application)
* include a payload (claims)

Claims should be a map using string keys.

[JWT tokens](https://en.wikipedia.org/wiki/JSON_Web_Token) (the default) fit these requirements and are widely supported in most languages using either hashed or cert based signing algorithms. However this is only one option. You can provide other behaviours like revocation, db tracking or another standard token type.

Tokens can be provided by any means, they can be put into HTTP request headers, cookies, sessions; really as long as you can get your token to your application you can verify it and use it.

Configuration of your token comes from two places:

1. token module - the token module that you're using provides some default options
2. Implementation module - you can provide custom options in your implementation module (the module that implements `Guardian` for your application).
