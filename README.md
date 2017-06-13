Guardian
========

> An authentication library for use with Elixir applications.

[![Build Status](https://travis-ci.org/ueberauth/guardian.svg?branch=master)](https://travis-ci.org/ueberauth/guardian)

> Looking for [Guardian pre 1.0](https://github.com/ueberauth/guardian/tree/v0.14.x)?

Guardian is a token based authentication library for use with Elixir applications.

Guardian remains a functional system. It integrates with Plug, but can be used outside of it. If you're implementing a TCP/UDP protocol directly, or want to utilize your authentication via channels in Phoenix, Guardian is your friend.

The core currency of authentication in Guardian is the _token_.
By default [JSON Web Tokens](https://jwt.io) are supported out of the box but any token that:

* Has the concept of a key-value payload
* Is tamper proof
* Can serialize to a String
* Has a supporting module that implements the `Guardian.Token` behaviour

Can be used with Guardian.

You can use Guardian tokens to authenticate:

* Web endpoints (Plug/Phoenix/X)
* Channels/Sockets (Phoenix - optional)
* Any other system you can imagine. If you can attach an authentication token you can authenticate it.

Tokens should be able to contain any assertions (claims) that a developer wants to make and may contain both standard and application specific information encoded within them.

Guardian also allows you to configure multiple token types/configurations in a single application.

## Useful articles

## Installation

Add Guardian to your application

mix.exs

```elixir
defp deps do
  [
    # ...
    {:guardian, "~> 1.0"}
    # ...
  ]
end
```

Create a module that uses `Guardian`

```elixir
defmodule MyApp.AuthTokens do
  use Guardian, otp_app: :my_app

  def subject_for_token(resource, _claims) do
    to_string(resource.id)
  end

  def resource_from_claims(claims) do
    find_me_a_resource(claims["sub"])
  end
end
```

Add your configuration

```elixir
config :my_app, MyApp.AuthTokens,
       issuer: "my_app"
       secret_key: "Secret key. You can use `mix phx.gen.secret` to get one"
```

With this level of configuration you can have a working installation.

## Basics

```elixir
# encode a token for a resource
{:ok, token, claims} = MyApp.AuthTokens.encode_and_sign(resource)

# decode and verify a token
{:ok, claims} = MyApp.AuthTokens.decode_and_verify(token)

# revoke a token (use GuardianDb or something similar if you need revoke to actually track a token)
{:ok, claims} = MyApp.AuthTokens.revoke(token)

# Refresh a token before it expires
{:ok, _old_stuff, {new_token, new_claims}} = MyApp.AuthTokens.refresh(token)

# Exchange a token of type "X" for a new token of type "Y"
{:ok, _old_stuff, {new_token, new_claims}} = MyApp.AuthTokens.exchange(token, "X", "Y")

# Lookup a resource directly from a token
{:ok, resource, claims} = MyApp.AuthTokens.resource_from_token(token)
```

## Configuration

The following configuration is available to all token modules.

* `token_module` - The module that implements the functions for dealing with tokens. Default `Guardian.Token.Jwt`

Guardian can handle tokens of any type that implement the `Guardian.Token` behaviour.
Each token module will have it's own configuration requirements. Please see below for the JWT configuration.

All configuration values may be provided in two ways.

1. In your config files
2. As a Keyword list to your call to `use Guardian` in you implementation module.

Any options given to `use Guardian` have precedence over config values found in the config files.

Some configuration may be required by your `token_module`

### Configuration values

Guardian resolves different types of configuration values. These can be provided in the config or options as:

* `{:system, "FOO"}` - Read from the system environment
* `{MyModule, :function_name}` - To call a function and use the result
* `{MyModule, :func, [:some, :args]}` Calls the function on the module with args
* `fn -> :some_value end` - an anonymous function whose result will be used
* any other value

These are evaluated at runtime and any value that you fetch via

`MyApp.AuthTokens.config(key, default)` will be resolved using this scheme.

See `Guardian.Config.resolve_value/1` for more information.

### JWT (Configuration)

The default token type of `Guardian` is Jwt. I accepts many options but you really only _need_ to specify the `issuer` and `secret_key`

#### Required configuration (JWT)

* `issuer` - The issuer of the token. Your application name/id
* `secret_key` - The secret key to use for the implementation module.
                 This may be any resolvable value for `Guardian.Config`

#### Optional configuration (JWT)

* `token_verify_module` - default `Guardian.Token.Jwt.Verify`. The module that verifies the claims
* `allowed_algos` - The allowed algos to use for encoding and decoding.
                    See `JOSE` for available. Default ["HS512"]
* `ttl` - The default time to live for all tokens. See the type in Guardian.ttl
* `token_ttl` a map of `token_type` to `ttl`. Set specific ttls for specific types of tokens
* `allowed_drift` The drift that is allowed when decoding/verifying a token in milli seconds
* `verify_issuer` Default false

## Secrets (JWT)

Secrets can be simple strings or more complicated `JOSE` secret schemes.

The simplest way to use the JWT module is to provide a simple String. (`mix phx.gen.secret` works great)

You can provide a system env string value by using `secret_key: {:system, "MY_TOKEN_SECRET"}` and setting the `MY_TOKEN_SECRET` in your environment.

Alternatively you can use a module and function by adding `secret_key: {MyModule, :function_name}`.

If you want to get a bit more in-depth:

By specifying a binary, the default behavior is to treat the key as an [`"oct"`](https://tools.ietf.org/html/rfc7518#section-6.4) key type (short for octet sequence). This key type may be used with the `"HS256"`, `"HS384"`, and `"HS512"` signature algorithms.

Alternatively, a configuration value that resolves to:

* `Map`
* `Function`
* `%JOSE.JWK{} Struct`

may be specified for other key types. A full list of example key types is available [here](https://gist.github.com/potatosalad/925a8b74d85835e285b9).

See the [key generation docs](https://hexdocs.pm/jose/key-generation.html) from jose for how to generate your own keys.

To get off the ground quickly, set your `secret_key` in your Guardian config with the output of either:

`$ mix phoenix.gen.secret`

or

`iex(1)> JOSE.JWS.generate_key(%{"alg" => "HS512"}) |> JOSE.JWK.to_map |> elem(1) |> Map.take(["k", "kty"])`

After running `$ mix deps.get` because JOSE is one of Guardian's dependencies.

```elixir
## Map ##

config :my_app, MyApp.AuthTokens,
  allowed_algos: ["ES512"],
  secret_key: %{
    "crv" => "P-521",
    "d" => "axDuTtGavPjnhlfnYAwkHa4qyfz2fdseppXEzmKpQyY0xd3bGpYLEF4ognDpRJm5IRaM31Id2NfEtDFw4iTbDSE",
    "kty" => "EC",
    "x" => "AL0H8OvP5NuboUoj8Pb3zpBcDyEJN907wMxrCy7H2062i3IRPF5NQ546jIJU3uQX5KN2QB_Cq6R_SUqyVZSNpIfC",
    "y" => "ALdxLuo6oKLoQ-xLSkShv_TA0di97I9V92sg1MKFava5hKGST1EKiVQnZMrN3HO8LtLT78SNTgwJSQHAXIUaA-lV"
  }

## Tuple ##
# If, for example, you have your secret key stored externally (in this example, we're using Redix).

# defined elsewhere
defmodule MySecretKey do
  def fetch do
    # Bad practice for example purposes only.
    # An already established connection should be used and possibly cache the value locally.
    {:ok, conn} = Redix.start_link
    rsa_jwk = conn
      |> Redix.command!(["GET my-rsa-key"])
      |> JOSE.JWK.from_binary
    Redix.stop(conn)
    rsa_jwk
  end
end

config :my_app, MyApp.AuthTokens,
  allowed_algos: ["RS512"],
  secret_key: {MySecretKey, :fetch}

## %JOSE.JWK{} Struct ##
# Useful if you store your secret key in an encrypted JSON file with the passphrase in an environment variable.

# defined elsewhere
defmodule MySecretKey do
  def fetch do
    System.get_env("SECRET_KEY_PASSPHRASE") |> JOSE.JWK.from_file(System.get_env("SECRET_KEY_FILE"))
  end
end

config :my_app, MyApp.AuthTokens,
  allowed_algos: ["Ed25519"],
  secret_key: {MySecretKey, :fetch}
```

## Using options in calls

Almost all of the functions provided by `Guardian` utilize options as the last argument.
These options are passed from the initiating call through to the `token_module` and also your `callbacks`. See the documentation for your `token_module` (`Guardian.Token.Jwt` by default) for more information.

## Hooks

Each implementation module (modules that `use Guardian`) implement callbacks for the `Guardian` behaviour. By default these are just pass-through but you can implement your own version to tweak the behaviour of your tokens.

The callbacks are:

* `after_encode_and_sign`
* `after_sign_in`
* `before_sign_out`
* `build_claims` - Use this to tweak the claims that you include in your token
* `default_token_type` - default is `"access"`
* `on_exchange`
* `on_revoke`
* `on_refresh`
* `on_verify`
* `verify_claims` - You can add custom validations for your tokens in this callback

## Plugs

### Pipelines

## Permissions

## Tracking Tokens

## Testing

## Related projects


----
### OLD README

config.exs

```elixir
config :guardian, Guardian,
  allowed_algos: ["HS512"], # optional
  verify_module: Guardian.JWT,  # optional
  issuer: "MyApp",
  ttl: { 30, :days },
  allowed_drift: 2000,
  verify_issuer: true, # optional
  secret_key: <guardian secret key>,
  serializer: MyApp.GuardianSerializer
```

The items in the configuration allow you to tailor how the JWT generation behaves.

* `allowed_algos` - The list of algorithms (must be compatible with JOSE). The first is used as the encoding key. Default is: ["HS512"]
* `verify_module` - Provides a mechanism to setup your own validations for items
  in the token. Default is `Guardian.JWT`
* `issuer` - The entry to put into the token as the issuer. This can be used in conjunction with `verify_issuer`
* `ttl` - The default ttl of a token
* `allowed_drift` - The allowable drift in miliseconds to allow for time fields. Allows for dealing with clock skew
* `verify_issuer` - If set to true, the issuer will be verified to be the same issuer as specified in the `issuer` field
* `secret_key` - The key to sign the tokens. See below for examples.
* `serializer` The serializer that serializes the 'sub' (Subject) field into and out of the token.

## Secret Key

By specifying a binary, the default behavior is to treat the key as an [`"oct"`](https://tools.ietf.org/html/rfc7518#section-6.4) key type (short for octet sequence). This key type may be used with the `"HS256"`, `"HS384"`, and `"HS512"` signature algorithms.

Alternatively, a `Map`, `Function`, or `%JOSE.JWK{} Struct` may be specified for other key types. A full list of example key types is available [here](https://gist.github.com/potatosalad/925a8b74d85835e285b9).

See the [key generation docs](https://hexdocs.pm/jose/key-generation.html) from jose for how to generate your own keys.

To get off the ground quickly, simply replace `<guardian secret key>` in your Guardian config with the output of either:

`$ mix phoenix.gen.secret`

or

`iex(1)> JOSE.JWS.generate_key(%{"alg" => "HS512"}) |> JOSE.JWK.to_map |> elem(1) |> Map.take(["k", "kty"])`

After running `$ mix deps.get` because JOSE is one of Guardian's dependencies.

```elixir
## Map ##

config :guardian, Guardian,
  allowed_algos: ["ES512"],
  secret_key: %{
    "crv" => "P-521",
    "d" => "axDuTtGavPjnhlfnYAwkHa4qyfz2fdseppXEzmKpQyY0xd3bGpYLEF4ognDpRJm5IRaM31Id2NfEtDFw4iTbDSE",
    "kty" => "EC",
    "x" => "AL0H8OvP5NuboUoj8Pb3zpBcDyEJN907wMxrCy7H2062i3IRPF5NQ546jIJU3uQX5KN2QB_Cq6R_SUqyVZSNpIfC",
    "y" => "ALdxLuo6oKLoQ-xLSkShv_TA0di97I9V92sg1MKFava5hKGST1EKiVQnZMrN3HO8LtLT78SNTgwJSQHAXIUaA-lV"
  }

## Tuple ##
# If, for example, you have your secret key stored externally (in this example, we're using Redix).

# defined elsewhere
defmodule MySecretKey do
  def fetch do
    # Bad practice for example purposes only.
    # An already established connection should be used and possibly cache the value locally.
    {:ok, conn} = Redix.start_link
    rsa_jwk = conn
      |> Redix.command!(["GET my-rsa-key"])
      |> JOSE.JWK.from_binary
    Redix.stop(conn)
    rsa_jwk
  end
end

config :guardian, Guardian,
  allowed_algos: ["RS512"],
  secret_key: {MySecretKey, :fetch}

## %JOSE.JWK{} Struct ##
# Useful if you store your secret key in an encrypted JSON file with the passphrase in an environment variable.

# defined elsewhere
defmodule MySecretKey do
  def fetch do
    System.get_env("SECRET_KEY_PASSPHRASE") |> JOSE.JWK.from_file(System.get_env("SECRET_KEY_FILE"))
  end
end

config :guardian, Guardian,
  allowed_algos: ["Ed25519"],
  secret_key: {MySecretKey, :fetch}
```

## Serializer

The serializer knows how to encode and decode your resource into and out of the
token. A simple serializer:

```elixir
defmodule MyApp.GuardianSerializer do
  @behaviour Guardian.Serializer

  alias MyApp.Repo
  alias MyApp.User

  def for_token(user = %User{}), do: { :ok, "User:#{user.id}" }
  def for_token(_), do: { :error, "Unknown resource type" }

  def from_token("User:" <> id), do: { :ok, Repo.get(User, id) }
  def from_token(_), do: { :error, "Unknown resource type" }
end
```

## Plug API

Guardian ships with some plugs to help integrate into your application.

### Guardian.Plug.VerifySession

Looks for a token in the session. Useful for browser sessions.
If one is not found, this does nothing.

### Guardian.Plug.VerifyHeader

Looks for a token in the Authorization header. Useful for apis.
If one is not found, this does nothing.

### Guardian.Plug.EnsureAuthenticated

Looks for a previously verified token. If one is found, continues, otherwise it
will call the `:unauthenticated` function of your handler.

When you ensure a session, you must declare an error handler. This can be done
as part of a pipeline or inside a Phoenix controller.

```elixir
defmodule MyApp.MyController do
  use MyApp.Web, :controller

  plug Guardian.Plug.EnsureAuthenticated, handler: MyApp.MyAuthErrorHandler
end
```

The failure function must receive the connection, and the connection params.

### Guardian.Plug.LoadResource

Up to now the other plugs have been just looking for valid tokens in various
places or making sure that the token has the correct permissions.

The `LoadResource` plug looks in the `sub` field of the token, fetches the
resource from the Serializer and makes it available via
`Guardian.Plug.current_resource(conn)`.

Note that this does _not ensure_ a resource will be loaded.
If there is no available resource (because it could not be found)
`current_resource` will return nil. You can ensure it's loaded with
`Guardian.Plug.EnsureResource`

### Guardian.Plug.EnsureResource

Looks for a previously loaded resource. If not found, the `:no_resource`
function is called on your handler.

```elixir
defmodule MyApp.MyController do
  use MyApp.Web, :controller

  plug Guardian.Plug.EnsureResource, handler: MyApp.MyAuthErrorHandler
end
```

### Guardian.Plug.EnsurePermissions

Looks for a previously verified token. If one is found, confirms that all listed
permissions are present in the token. If not, the `:unauthorized` function is called on your handler.

```elixir
defmodule MyApp.MyController do
  use MyApp.Web, :controller

  plug Guardian.Plug.EnsurePermissions, handler: MyApp.MyAuthErrorHandler, default: [:read, :write]
end
```

When permissions' sets are specified through a `:one_of` map, the token is searched for at least one
matching permissions set to allow the request. The first set that matches will allow the request.
If no set matches, the `:unauthorized` function is called.

```elixir
defmodule MyApp.MyController do
  use MyApp.Web, :controller

  plug Guardian.Plug.EnsurePermissions, handler: MyApp.MyAuthErrorHandler,
    one_of: [%{default: [:read, :write]}, %{other: [:read]}]
end
```

### Pipelines

These plugs can be used to construct pipelines in Phoenix.

```elixir
pipeline :browser_session do
  plug Guardian.Plug.VerifySession
  plug Guardian.Plug.LoadResource
end

pipeline :api do
  plug :accepts, ["json"]
  plug Guardian.Plug.VerifyHeader
  plug Guardian.Plug.LoadResource
end

scope "/", MyApp do
  pipe_through [:browser, :browser_session] # Use the default browser stack
  # ...
end

scope "/api", MyApp.Api do
  pipe_through [:api] # Use the default browser stack
end
```

From here, you can either EnsureAuthenticated in your pipeline, or on a per-controller basis.

```elixir
defmodule MyApp.MyController do
  use MyApp.Web, :controller

  plug Guardian.Plug.EnsureAuthenticated, handler: MyApp.MyAuthHandler
end
```

## Sign in and Sign out

It's up to you how you generate the claims to encode into the token Guardian uses.
As an example, here are the important parts of a SessionController

```elixir
defmodule MyApp.SessionController do
  use MyApp.Web, :controller

  alias MyApp.User
  alias MyApp.UserQuery

  plug :scrub_params, "user" when action in [:create]

  def create(conn, params = %{}) do
    conn
    |> put_flash(:info, "Logged in.")
    |> Guardian.Plug.sign_in(verified_user) # verify your logged in resource
    |> redirect(to: user_path(conn, :index))
  end

  def delete(conn, _params) do
    Guardian.Plug.sign_out(conn)
    |> put_flash(:info, "Logged out successfully.")
    |> redirect(to: "/")
  end
end
```

### Guardian.Plug.sign\_in

You can sign in with a resource (that the serializer knows about)

```elixir
Guardian.Plug.sign_in(conn, user) # Sign in with the default storage
```

```elixir
Guardian.Plug.sign_in(conn, user, :access, claims)  # give some claims to used for the token jwt

Guardian.Plug.sign_in(conn, user, :access, key: :secret)  # create a token in the :secret location
```

To attach permissions to the token, use the `:perms` key and pass it a map.
Note. To add permissions, you should configure them in your guardian config.

```elixir
Guardian.Plug.sign_in(conn, user, :access, perms: %{ default: [:read, :write], admin: [:all] })

Guardian.Plug.sign_in(conn, user, :access, key: :secret, perms: %{ default: [:read, :write], admin: [:all]})  # create a token in the :secret location
```

### Guardian.Plug.sign\_out

```elixir
Guardian.Plug.sign_out(conn) # Sign out everything (clear session)
```

```elixir
Guardian.Plug.sign_out(conn, :secret) # Clear the token and associated user from the 'secret' location
```

### Current resource, token and claims

Access to the current resource, token and claims is useful. Note, you'll need to
have run the VerifySession/Header for token and claim access, and LoadResource to access the resource.

```elixir
Guardian.Plug.claims(conn) # Access the claims in the default location
Guardian.Plug.claims(conn, :secret) # Access the claims in the secret location
```

```elixir
Guardian.Plug.current_token(conn) # access the token in the default location
Guardian.Plug.current_token(conn, :secret) # access the token in the secret location
```

For the resource

```elixir
Guardian.Plug.current_resource(conn) # Access the loaded resource in the default location
Guardian.Plug.current_resource(conn, :secret) # Access the loaded resource in the secret location
```

### Without Plug

There are many instances where Plug might not be in use. Channels, and raw
sockets for e.g. If you need to do things your own way.

```elixir
{ :ok, jwt, encoded_claims } = Guardian.encode_and_sign(resource, <token_type>, claims_map)
```

This will give you a new JWT to use with the claims ready to go.
The token type is encoded into the JWT as the 'typ' field and is intended to be
used as the _type_ of "access".

```elixir
{ :ok, jwt, full_claims } = Guardian.encode_and_sign(resource, :access)
```

Add some permissions

```elixir
{ :ok, jwt, full_claims } = Guardian.encode_and_sign(resource, :access, perms: %{ default: [:read, :write], admin: Guardian.Permissions.max})
```

Currently suggested token types are:

* `"access"` - Use for API or CORS access. These are basic tokens.

You can also customize the claims you're asserting.

```elixir
claims = Guardian.Claims.app_claims
         |> Map.put("some_claim", some_value)
         |> Guardian.Claims.ttl({3, :days})

{ :ok, jwt, full_claims } = Guardian.encode_and_sign(resource, :access, claims)
```

To verify the token:

```elixir
case Guardian.decode_and_verify(jwt) do
  { :ok, claims } -> do_things_with_claims(claims)
  { :error, reason } -> do_things_with_an_error(reason)
end
```

Accessing the resource from a set of claims:

```elixir
case Guardian.serializer.from_token(claims["sub"]) do
  { :ok, resource } -> do_things_with_resource(resource)
  { :error, reason } -> do_things_without_a_resource(reason)
end
```

### Permissions

Guardian includes support for including permissions. Declare your permissions in
your configuration. All known permissions must be included.

```elixir
config :guardian, Guardian,
       permissions: %{
         default: [:read, :write],
         admin: [:dashboard, :reconcile]
       }
```

JWTs need to be kept reasonably small so that they can fit into an authorization
header. For this reason, permissions are encoded as bits (an integer) in the
token. You can have up to 64 permissions per set, and as many sets as you like.
In the example above, we have the `:default` set, and the `:admin` set.

The bit value of the permissions within a set is determined by it's position in
the config.

```elixir
# Fetch permissions from the claims map

Guardian.Permissions.from_claims(claims, :default)
Guardian.Permissions.from_claims(claims, :admin)

# Check the permissions for all present

Guardian.Permissions.from_claims(claims, :default) |> Guardian.Permissions.all?([:read, :write], :default)
Guardian.Permissions.from_claims(claims, :admin) |> Guardian.Permissions.all?([:reconcile], :admin)

# Check for any permissions
Guardian.Permissions.from_claims(claims, :default) |> Guardian.Permissions.any?([:read, :write], :default)
Guardian.Permissions.from_claims(claims, :admin) |> Guardian.Permissions.any?([:reconcile, :dashboard], :admin)
```

You can use a plug to ensure permissions are present. See Guardian.Plug.EnsurePermissions

#### Setting permissions

When you generate (or sign in) a token, you can inject permissions into it.

```elixir
Guardian.encode_and_sign(resource, :access, perms: %{ admin: [:dashboard], default: Guardian.Permissions.max}})
```

By setting a permission using Guardian.Permission.max you're setting all the bits, so even if new permissions are added, they will be set.

You can similarly pass a `:perms` key to the sign\_in method to have the
permissions encoded into the token.

### Hooks

Often you'll need to take action on some event within the lifecycle of
authentication. Recording logins etc. Guardian provides hooks to allow you to do
this. Use the Guardian.Hooks module to setup. Default implementations are
available for all callbacks.

```elixir
defmodule MyApp.GuardianHooks do
  use Guardian.Hooks

  def after_sign_in(conn, location) do
    user = Guardian.Plug.current_resource(conn, location)
    IO.puts("SIGNED INTO LOCATION WITH: #{user.email}")
    conn
  end
end
```

By default, JWTs are not tracked. This means that after 'logout' the token can
still be used if it is stored outside the system. This is because Guardian does
not track tokens and only interprets them live. When using Guardian in this
way, be sure you consider the expiry time as this is one of the few options you
have to make your tokens invalid.

If you want more control over this you should implement a hook that tracks the
tokens in some storage. When calling `Guardian.revoke!` (called automatically
with sign\_out).

To keep track of all tokens and ensure they're revoked on sign out you can use
[GuardianDb](https://github.com/hassox/guardian_db). This is a simple
Guardian.Hooks module that implements database integration.

    config :guardian, Guardian,
           hooks: GuardianDb

    config :guardian_db, GuardianDb, repo: MyRepo

Configure Guardian to know which module to use.

```elixir
config :guardian, Guardian,
       hooks: MyApp.GuardianHooks,
       #…
```

### Refreshing Tokens

You can use Guardian to refresh tokens. This keeps most of the information in
the token intact, but changes the `iat`, `exp`, `jti` and `nbf` fields.
A valid token must be used in order to be refreshed,
see [Refresh Tokens](###Refresh Tokens) for information on how to refresh invalid tokens

```elixir
case Guardian.refresh!(existing_jwt, existing_claims, %{ttl: {15, :days}}) do
  {:ok, new_jwt, new_claims} -> do_things(new_jwt)
  {:error, reason} -> handle_error(reason)
end
```

Once the new token is created, the old one is revoked before returning the new
token.

### Exchange Tokens

You can exchange one type of token to an other given that the first is valid
This can be used to issue long living tokens that can be exchanged for shorter living ones

```elixir
    # issue a long living refresh token
    {:ok, jwt, claims} = Guardian.encode_and_sign(resource, "refresh")
    # exchange the refresh token for a access token
    {:ok, access_jwt, new_claims} = Guardian.exchange(jwt, "refresh", "access")
```


The old token wont be revoked after the exchange

```elixir
    # issue a long living refresh token
    {:ok, jwt, claims} = Guardian.encode_and_sign(resource, "refresh")
    # exchange the refresh token for a access token
    {:ok, new_jwt, new_claims} = Guardian.exchange!(jwt)
```


### Phoenix Controllers

Guardian provides some helpers for you to use with your controllers.

Provides a simple helper to provide easier access to the current user and their claims.

```elixir
defmodule MyApp.MyController do
  use MyApp.Web, :controller
  use Guardian.Phoenix.Controller

  def index(conn, params, user, claims) do
    # do stuff in here
  end
end
```

You can specify the key location of the user if you're using multiple locations to store users.

```elixir
defmodule MyApp.MyController do
  use MyApp.Web, :controller
  use Guardian.Phoenix.Controller, key: :secret

  def index(conn, params, user, claims) do
  # do stuff with the secret user
  end
end
```

### Phoenix Sockets

Guardian provides integration into the Phoenix channels API to provide
authentication. You can choose to authenticate either on `connect` or every time
someone joins a topic.

To authenticate the initial connect there's a couple of options.

1. Automatically authenticate
2. Authenticate with more control manually.

To automatically authenticate `use` the Guardian.Phoenix.Socket module in your
socket.

```elixir
defmodule MyApp.UsersSocket do
  use Phoenix.Socket
  use Guardian.Phoenix.Socket

  def connect(_params, socket) do
    # if we get here, we did not authenticate
    :error
  end
end
```

Connection authentication requires a `guardian_token` parameter to be provided
which is the JWT. If this is present, Guardian.Phoenix.Socket will authenticate
the connection and carry on or return an `:error` and not allow the connection.

On the javascript side provide your token when you connect.

```javascript
let socket = new Socket("/ws");
socket.connect({guardian_token: jwt});
```

This works fine when all connections should be authenticated. In the case where
you want some of them to be, you can manually sign in.

```elixir
defmodule MyApp.UsersSocket do
  use Phoenix.Socket
  import Guardian.Phoenix.Socket

  def connect(%{"guardian_token" => jwt} = params, socket) do
    case sign_in(socket, jwt) do
      {:ok, authed_socket, guardian_params} ->
        {:ok, authed_socket}
      _ ->
        #unauthenticated socket
        {:ok, socket}
    end
  end

  def connect(_params, socket) do
    # handle unauthenticated connection
  end
end
```

Once you have an authenticated socket you can get the information from it:

```elixir
claims = Guardian.Phoenix.Socket.current_claims(socket)
jwt = Guardian.Phoenix.Socket.current_token(socket)
user = Guardian.Phoenix.Socket.current_resource(socket)
```

If you need even more control, you can use the helpers provided by
Phoenix.Guardian.Socket inside your Channel.

### Phoenix Channels

We can use the Guardian.Phoenix.Socket module to help authenticate channels.

```elixir
defmodule MyApp.UsersChannel do
  use Phoenix.Channel
  import Guardian.Phoenix.Socket

  def join(_room, %{"guardian_token" => token}, socket) do
    case sign_in(socket, token) do
      {:ok, authed_socket, _guardian_params} ->
        {:ok, %{message: "Joined"}, authed_socket}
      {:error, reason} ->
        # handle error
    end
  end

  def join(room, _, socket) do
    {:error,  :authentication_required}
  end

  def handle_in("ping", _payload, socket) do
    user = current_resource(socket)
    broadcast(socket, "pong", %{message: "pong", from: user.email})
    {:noreply, socket}
  end
end
```

Guardian picks up on joins that have been made and automatically verifies the
token and makes available the claims and resource making the request.

```javascript
let socket = new Socket("/ws");
socket.connect();
let guardianToken = jQuery('meta[name="guardian_token"]').attr('content');
let chan = socket.chan("pings", { guardian_token: guardianToken });
```

How to get the tokens onto the page?

```eex
<%= if Guardian.Plug.current_token(@conn) do %>
  <meta name='guardian_token' content="<%= Guardian.Plug.current_token(@conn) %>">
<% end %>
```

# Acknowledgements

Many thanks to Sonny Scroggin (@scrogson) for the name Guardian and great
feedback to get up and running.

### TODO

- [x] Flexible serialization
- [x] Integration with Plug
- [x] Basic integrations like raw TCP
- [x] Service2Service credentials. That is, pass the authentication results through many downstream requests.
- [x] Integration with Phoenix channels
- [x] Integrated permission sets
- [x] Hooks into the authentication cycle
- [x] Revoke tokens
- [x] Refresh tokens
