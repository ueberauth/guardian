# JWT Tokens

The default implementation of a Token in Guardian is [JWT](https://en.wikipedia.org/wiki/JSON_Web_Token).

The default payload of a JWT token produced by Guardian contains the following:

- `iss` (Issuer): Identifies principal that issued the JWT. This normally comes from your application config, e.g. `config :idp, Idp.Auth.Guardian, issuer: "idp"`.
- `sub` (Subject): Identifies the subject. Identifies the subject of the JWT, e.g. `User:123`.
- `aud` (Audience): Identifies the recipients that the JWT is intended for. By default it is the same as `iss`.
- `exp` (Expiration Time): Identifies the expiration time on and after which the token will become invalid. It is represented as a unix timestamp.
  The expiration time is set via the option `exp`. By default it's 4 weeks in Guardian.
- `iat` (Issued at): Identifies the time at which the JWT was issued. It is represented as a unix timestamp.
- `nbf` (Not before): Identifies the time at which the JWT will start to be accepted for processing. It is represented as a unix timestamp.
  By default it is set to be 1 ms before `iat`.
- `typ` (Token Type): The type of the token. By default it is `"access"`.
  Note that this is not the same as the `typ` entry in the JWT's **header**, which will always be `"JWT"`.
- `jti` (JWT ID): The unique id of the token.

You can add custom claims additionally when calling the function `Guardian.encode_and_sign`.

For further information, refer to the module [Guardian.Token.Jwt](https://hexdocs.pm/guardian/Guardian.Token.Jwt.html).
