# Guardian

> An authentication library for use with Elixir applications.

[![Build Status](https://travis-ci.org/ueberauth/guardian.svg?branch=master)](https://travis-ci.org/ueberauth/guardian)
[![Codecov](https://codecov.io/gh/ueberauth/guardian/branch/master/graph/badge.svg)](https://codecov.io/gh/ueberauth/guardian)
[![Inline docs](http://inch-ci.org/github/ueberauth/guardian.svg)](http://inch-ci.org/github/ueberauth/guardian)
[![Module Version](https://img.shields.io/hexpm/v/guardian.svg)](https://hex.pm/packages/guardian)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/guardian/)
[![Total Download](https://img.shields.io/hexpm/dt/guardian.svg)](https://hex.pm/packages/guardian)
[![License](https://img.shields.io/hexpm/l/guardian.svg)](https://github.com/ueberauth/guardian/blob/master/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/ueberauth/guardian.svg)](https://github.com/ueberauth/guardian/commits/master)

Guardian is a token based authentication library for use with Elixir applications.

Guardian remains a functional system. It integrates with Plug but can be used outside of it. If you're implementing a TCP/UDP protocol directly or want to utilize your authentication via channels in Phoenix, Guardian can work for you.

The core currency of authentication in Guardian is the _token_.
By default [JSON Web Tokens](https://jwt.io) are supported out of the box but you can use any token that:

* Has the concept of a key-value payload
* Is tamper proof
* Can serialize to a String
* Has a supporting module that implements the `Guardian.Token` behaviour

You can use Guardian tokens to authenticate:

* Web endpoints (Plug/Phoenix/X)
* Channels/Sockets (Phoenix - optional)
* Any other system you can imagine. If you can attach an authentication token you can authenticate it.

Tokens should be able to contain any assertions (claims) that a developer wants to make and may contain both standard and application specific information encoded within them.

Guardian also allows you to configure multiple token types/configurations in a single application.

## Documentation

API documentation is available at [https://hexdocs.pm/guardian](https://hexdocs.pm/guardian)

## Installation


Add Guardian to your application to your list of dependencies in `mix.exs`:

```elixir
defp deps do
  [
    {:guardian, "~> 2.0"}
  ]
end
```

In order to leverage Guardian we'll need first create an "implementation module" which includes Guardian's functionality and the code for encoding and decoding our token's values.
To do this, create a module that uses `Guardian` and implements the `subject_for_token/2` and `resource_from_claims/1` function.

```elixir
defmodule MyApp.Guardian do
  use Guardian, otp_app: :my_app

  def subject_for_token(%{id: id}, _claims) do
    # You can use any value for the subject of your token but
    # it should be useful in retrieving the resource later, see
    # how it being used on `resource_from_claims/1` function.
    # A unique `id` is a good subject, a non-unique email address
    # is a poor subject.
    sub = to_string(id)
    {:ok, sub}
  end
  def subject_for_token(_, _) do
    {:error, :reason_for_error}
  end

  def resource_from_claims(%{"sub" => id}) do
    # Here we'll look up our resource from the claims, the subject can be
    # found in the `"sub"` key. In above `subject_for_token/2` we returned
    # the resource id so here we'll rely on that to look it up.
    resource = MyApp.get_resource_by_id(id)
    {:ok,  resource}
  end
  def resource_from_claims(_claims) do
    {:error, :reason_for_error}
  end
end
```

Next we need to add our configuration to `config/config.exs`:

```elixir
config :my_app, MyApp.Guardian,
       issuer: "my_app",
       secret_key: "Secret key. You can use `mix guardian.gen.secret` to get one"
```

Congrats! We have a working Guardian implementation.

## Basics

```elixir
# encode a token for a resource
{:ok, token, claims} = MyApp.Guardian.encode_and_sign(resource)

# decode and verify a token
{:ok, claims} = MyApp.Guardian.decode_and_verify(token)

# revoke a token (use GuardianDb or something similar if you need revoke to actually track a token)
{:ok, claims} = MyApp.Guardian.revoke(token)

# Refresh a token before it expires
{:ok, _old_stuff, {new_token, new_claims}} = MyApp.Guardian.refresh(token)

# Exchange a token of type "refresh" for a new token of type "access"
{:ok, _old_stuff, {new_token, new_claims}} = MyApp.Guardian.exchange(token, "refresh", "access")

# Lookup a resource directly from a token
{:ok, resource, claims} = MyApp.Guardian.resource_from_token(token)
```

With Plug:

```elixir
# If a session is loaded the token/resource/claims will be put into the session and connection
# If no session is loaded, the token/resource/claims only go onto the connection
conn = MyApp.Guardian.Plug.sign_in(conn, resource)

# Optionally with claims and options
conn = MyApp.Guardian.Plug.sign_in(conn, resource, %{some: "claim"}, ttl: {1, :minute})

# remove from session (if fetched) and revoke the token
# can also clear the remember me token, if the option :clear_remember_me is set
conn = MyApp.Guardian.Plug.sign_out(conn)

# Set a "refresh" token directly on a cookie.
# Can be used in conjunction with `Guardian.Plug.VerifyCookie` and `Guardian.Plug.SlidingCookie`
conn = MyApp.Guardian.Plug.remember_me(conn, resource)

# Fetch the information from the current connection
token = MyApp.Guardian.Plug.current_token(conn)
claims = MyApp.Guardian.Plug.current_claims(conn)
resource = MyApp.Guardian.Plug.current_resource(conn)
```

Creating with custom claims and options:

```elixir
# Add custom claims to a token
{:ok, token, claims} = MyApp.Guardian.encode_and_sign(resource, %{some: "claim"})

# Create a specific token type (i.e. "access"/"refresh" etc)
{:ok, token, claims} = MyApp.Guardian.encode_and_sign(resource, %{}, token_type: "refresh")

# Customize the time to live (ttl) of the token
{:ok, token, claims} = MyApp.Guardian.encode_and_sign(resource, %{}, ttl: {1, :minute})

# Customize the secret
{:ok, token, claims} = MyApp.Guardian.encode_and_sign(resource, %{}, secret: "custom")
{:ok, token, claims} = MyApp.Guardian.encode_and_sign(resource, %{}, secret: {SomeMod, :some_func, ["some", "args"]})

# Require an "auth_time" claim to be added.
{:ok, token, claims} = MyApp.Guardian.encode_and_sign(resource, %{}, auth_time: true)
```

Decoding tokens:

```elixir
# Check some literal claims. (i.e. this is an access token)
{:ok, claims} = MyApp.Guardian.decode_and_verify(token, %{"typ" => "access"})

# Use a custom secret
{:ok, claims} = MyApp.Guardian.decode_and_verify(token, %{}, secret: "custom")
{:ok, claims} = MyApp.Guardian.decode_and_verify(token, %{}, secret: {SomeMod, :some_func, ["some", "args"]})

# Specify a maximum age (since end user authentication time). If the token has an
# `auth_time` claim and it is older than the `max_age` allows, the token will be invalid.
{:ok, claims} = MyApp.Guardian.decode_and_verify(token, %{}, max_age: {2, :hours})
```

If you need dynamic verification for JWT tokens, please see the documentation for `Guardian.Token.Jwt` and `Guardian.Token.Jwt.SecretFetcher`.

## Configuration

The following configuration is available to all implementation modules.

* `token_module` - The module that implements the functions for dealing with tokens. Default `Guardian.Token.Jwt`.

Guardian can handle tokens of any type that implements the `Guardian.Token` behaviour.
Each token module will have its own configuration requirements. Please see below for the JWT configuration.

All configuration values may be provided in two ways.

1. In your config files
2. As a Keyword list to your call to `use Guardian` in your implementation module.

Any options given to `use Guardian` have precedence over config values found in the config files.

Some configuration may be required by your `token_module`.

### Configuration values

Guardian supports resolving configuration options at runtime, to that we use the following syntax:

* `{MyModule, :func, [:some, :args]}` Calls the function on the module with args

These are evaluated at runtime and any value that you fetch via

`MyApp.Guardian.config(key, default)` will be resolved using this scheme.

See `Guardian.Config.resolve_value/1` for more information.

### JWT (Configuration)

The default token type of `Guardian` is JWT. It accepts many options but you really only _need_ to specify the `issuer` and `secret_key`.

#### Required configuration (JWT)

* `issuer` - The issuer of the token. Your application name/id
* `secret_key` - The secret key to use for the implementation module.
  This may be any resolvable value for `Guardian.Config`.

#### Optional configuration (JWT)

* `token_verify_module` - default `Guardian.Token.Jwt.Verify`. The module that verifies the claims
* `allowed_algos` - The allowed algos to use for encoding and decoding.
  See `JOSE` for available. Default `["HS512"]`
* `ttl` - The default time to live for all tokens. See the type in Guardian.ttl
* `token_ttl` a map of `token_type` to `ttl`. Set specific ttls for specific types of tokens
* `allowed_drift` The drift that is allowed when decoding/verifying a token in milliseconds
* `verify_issuer` Default false
* `secret_fetcher` A module used to fetch the secret. Default: `Guardian.Token.Jwt.SecretFetcher`
* `auth_time` Include an `auth_time` claim to denote the end user authentication time. Default false.
* `max_age` Specify the maximum time (since the end user authentication) the token will be valid.
  Format is the same as `ttl`. Implies `auth_time` unless `auth_time` is set explicitly to `false`.

See the [OpenID Connect Core specification](https://openid.net/specs/openid-connect-core-1_0.html)
for more details about `auth_time` and `max_age` behaviour.

## Secrets (JWT)

Secrets can be simple strings or more complicated `JOSE` secret schemes.

The simplest way to use the JWT module is to provide a simple String. (`mix guardian.gen.secret` works great)

Alternatively you can use a module and function by adding `secret_key: {MyModule, :function_name, [:some, :args]}`.

More advanced secret information can be found below.

## Using options in calls

Almost all of the functions provided by `Guardian` utilize options as the last argument.
These options are passed from the initiating call through to the `token_module` and also your `callbacks`. See the documentation for your `token_module` (`Guardian.Token.Jwt` by default) for more information.

## Hooks

Each implementation module (modules that `use Guardian`) implement callbacks for the `Guardian` behaviour. By default, these are just pass-through but you can implement your own version to tweak the behaviour of your tokens.

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

Guardian provides various plugs to help work with web requests in Elixir.
Guardians plugs are optional and will not be compiled if you're not using Plug in your application.

All plugs need to be in a `pipeline`.
A pipeline is just a way to get the implementation module and error handler
into the connection for use downstream. More information can be found in the `Pipelines` section.

### Plugs and keys (advanced usage)

All Plugs and related functions provided by `Guardian` have the concept of a `key`.
A `key` specifies a label that is used to keep tokens separate so that you can have multiple token/resource/claims active in a single request.

In your plug pipeline you may use something like:

```elixir
plug Guardian.Plug.VerifyHeader, key: :impersonate
plug Guardian.Plug.EnsureAuthenticated, key: :impersonate
```

In your action handler:

```elixir
resource = MyApp.Guardian.Plug.current_resource(conn, key: :impersonate)
claims = MyApp.Guardian.Plug.current_claims(conn, key: :impersonate)
```

### Plugs out of the box

#### `Guardian.Plug.VerifyHeader`

Look for a token in the header and verify it

#### `Guardian.Plug.VerifySession`

Look for a token in the session and verify it

#### `Guardian.Plug.VerifyCookie`
**NOTE**: this plug is deprecated. Please use `:refresh_from_cookie` option in `Guardian.Plug.VerifyHeader` or `Guardian.Plug.VerifySession`

Look for a token in cookies and exchange it for an access token

#### `Guardian.Plug.SlidingCookie`

Replace the token in cookies with a new one when a configured minimum TTL
is remaining.

#### `Guardian.Plug.EnsureAuthenticated`

Make sure that a token was found and is valid

#### `Guardian.Plug.EnsureNotAuthenticated`

Make sure no one is logged in

#### `Guardian.Plug.LoadResource`

If a token was found, load the resource for it

See the documentation for each Plug for more information.

### Pipelines

A pipeline is a way to collect together the various plugs for a particular authentication scheme.

Apart from keeping an authentication flow together, pipelines provide downstream information for error handling and which implementation module to use. You can provide this separately but we recommend creating a pipeline plug.

#### Create a custom pipeline

```elixir
defmodule MyApp.AuthAccessPipeline do
  use Guardian.Plug.Pipeline, otp_app: :my_app

  plug Guardian.Plug.VerifySession, claims: %{"typ" => "access"}
  plug Guardian.Plug.VerifyHeader, claims: %{"typ" => "access"}
  plug Guardian.Plug.EnsureAuthenticated
  plug Guardian.Plug.LoadResource, allow_blank: true
end
```

By default, the LoadResource plug will return an error if no resource can be found.
You can override this behaviour using the `allow_blank: true` option.

Add your implementation module and error handler to your configuration:

```elixir
config :my_app, MyApp.AuthAccessPipeline,
  module: MyApp.Guardian,
  error_handler: MyApp.AuthErrorHandler
```

By using a pipeline, apart from keeping your auth logic together, you're instructing downstream plugs to use a particular implementation module and error handler.

If you wanted to do that manually:

```elixir
plug Guardian.Plug.Pipeline, module: MyApp.Guardian,
                             error_handler: MyApp.AuthErrorHandler

plug Guardian.Plug.VerifySession
```

### Plug Error Handlers

The error handler is a module that implements an `auth_error` function:

```elixir
defmodule MyApp.AuthErrorHandler do
  import Plug.Conn

  @behaviour Guardian.Plug.ErrorHandler

  @impl Guardian.Plug.ErrorHandler
  def auth_error(conn, {type, _reason}, _opts) do
    body = Jason.encode!(%{message: to_string(type)})

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, body)
  end
end
```

### Phoenix

Guardian and Phoenix are perfect together, but to get the most out of the integration be sure to include the [`guardian_phoenix`](https://github.com/ueberauth/guardian_phoenix) library.

See the Guardian Phoenix documentation for more information.

## Permissions

Permissions can be encoded into your token as an optional add-in.

Encoding permissions into a token is useful in some areas of authorization.
The permissions provided by `Guardian.Permissions` have one level of nesting.

For example:

* `users -> profile_read`
* `users -> profile_write`
* `users -> followers_read`
* `users -> followers_write`
* `admin -> all_users_read`
* `admin -> all_users_write`

Once a permission is granted it is valid for as long as the token is valid.
Since the permission is valid for the life of a token it is not suitable to encode highly dynamic information into a token. These permissions are similar in intent to OAuth scopes. Very useful as a broad grant to an area of code for 3rd party services / other microservices. If you have a requirement to look up permissions from your database for a particular user on each request, these are not the permissions you're looking for.

Please see `Guardian.Permissions` for more information.

## Tracking Tokens

When using tokens, depending on the type of token you use, nothing may happen by default when you `revoke` a token.

For example, JWT tokens by default are not tracked by the application.
The fact that they are signed with the correct secret and are not expired is usually how validation of if a token is active or not. Depending on your use-case this may not be enough for your application needs.
If you need to track and revoke individual tokens, you may need to use something like
[GuardianDb](https://github.com/ueberauth/guardian_db).

This will record each token issued in your database, confirm it is still valid on each access and then finally when you `revoke` (called on sign_out or manually) invalidate the token.

For more in-depth documentation please see the [GuardianDb README](https://github.com/ueberauth/guardian_db/blob/master/README.md).

## Best testing practices

### How to add the token to a request (the Phoenix way)

Assuming you are using the default authentication scheme `Bearer` for
the `Authorization` header:

```elixir
defmodule HelloWeb.AuthControllerTest do
  use HelloWeb.ConnCase
  import HelloWeb.Guardian

 test "GET /auth/me", %{conn: conn} do
    user = insert(:user) # See https://github.com/thoughtbot/ex_machina

    {:ok, token, _} = encode_and_sign(user, %{}, token_type: :access)

    conn = conn
    |> put_req_header("authorization", "Bearer " <> token)
    |> get(auth_path(conn, :me))

    # Assert things here
  end

end
```

## Related projects

* [GuardianDb](https://github.com/ueberauth/guardian_db) - Token tracking in the database
* [GuardianPhoenix](https://github.com/ueberauth/guardian_phoenix) - Phoenix integration
* [sans_password](https://hex.pm/packages/sans_password) - A simple, passwordless authentication system based on Guardian.
* [protego](https://hex.pm/packages/protego) - Flexible authentication solution for Elixir/Phoenix with Guardian.

## More advanced secrets

By specifying a binary, the default behavior is to treat the key as an [`"oct"`](https://tools.ietf.org/html/rfc7518#section-6.4) key type (short for octet sequence). This key type may be used with the `"HS256"`, `"HS384"`, and `"HS512"` signature algorithms.

Alternatively, a configuration value that resolves to:

* `Map`
* `Function`
* `%JOSE.JWK{} Struct`

May be specified for other key types. A full list of example key types is available [here](https://gist.github.com/potatosalad/925a8b74d85835e285b9).

See the [key generation docs](https://hexdocs.pm/jose/key-generation.html) from Jose for how to generate your own keys.

To get off the ground quickly, set your `secret_key` in your Guardian config with the output of either:

```bash
$ mix guardian.gen.secret`
```

or

```elixir
iex> JOSE.JWS.generate_key(%{"alg" => "HS512"}) |> JOSE.JWK.to_map |> elem(1) |> Map.take(["k", "kty"])
```

After running `$ mix deps.get` because JOSE is one of Guardian's dependencies:

```elixir
## Map ##

config :my_app, MyApp.Guardian,
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

config :my_app, MyApp.Guardian,
  allowed_algos: ["RS512"],
  secret_key: {MySecretKey, :fetch, []}

## %JOSE.JWK{} Struct ##
# Useful if you store your secret key in an encrypted JSON file with the passphrase in an environment variable.

# defined elsewhere
defmodule MySecretKey do
  def fetch do
    System.get_env("SECRET_KEY_PASSPHRASE") |> JOSE.JWK.from_file(System.get_env("SECRET_KEY_FILE"))
  end
end

config :my_app, MyApp.Guardian,
  allowed_algos: ["Ed25519"],
  secret_key: {MySecretKey, :fetch, []}
```
### Private/Public Keypairs

A full example of how to configure guardian to use private/public key files as secrets, can be found [here](https://github.com/ueberauth/guardian_pemfile_config_example).

### Key Rotation

Guardian provides a `Guardian.Token.Jwt.SecretFetcher` behaviour that allows custom keys to be used for signing and verifying requests.
This makes it possible to rotate private keys while maintaining a list of valid public keys that can be used both for validating signatures as well as serving public keys to external services.

Below is a simple example of how this can be implemented using a `GenServer`.


```elixir
defmodule MyApp.Guardian.KeyServer do
  @moduledoc ~S"""
  A simple GenServer implementation of a custom `Guardian.Token.Jwt.SecretFetcher`
  This is appropriate for development but should not be used in production
  due to questionable private key storage, lack of multi-node support,
  node restart durability, and public key garbage collection.
  """

  use GenServer

  @behaviour Guardian.Token.Jwt.SecretFetcher

  @impl Guardian.Token.Jwt.SecretFetcher
  # This will always return a valid key as a new one will be generated
  # if it does not already exist.
  def fetch_signing_secret(_mod, _opts),
    do: {:ok, GenServer.call(__MODULE__, :fetch_private_key)}

  @impl Guardian.Token.Jwt.SecretFetcher
  # This assumes that the adapter properly assigned a key id (kid)
  # to the signing key. Make sure it's there! with something like
  # JOSE.JWK.merge(jwk, %{"kid" => JOSE.JWK.thumbprint(jwk)})
  # see https://tools.ietf.org/html/rfc7515#section-4.1.4
  # for details
  def fetch_verifying_secret(_mod, %{"kid" => kid}, _opts) do
    case GenServer.call(__MODULE__, {:fetch_public_key, kid}) do
      {:ok, public_key} -> {:ok, public_key}
      :error -> {:error, :secret_not_found}
    end
  end

  def fetch_verifying_secret(_, _, _), do: {:error, :secret_not_found}

  # This is not a defined callback for the SecretFetcher, but could be useful
  # for providing an endpoint that external services could use to verify tokens
  # for themselves.
  def fetch_verifying_secrets,
    do: GenServer.call(__MODULE__, :fetch_public_keys)

  # Expire the private key so that a new one will be generated on the next
  # signing request. The public key associated with the old private key should
  # be stored at the very least as long as the largest possible "exp"
  # (https://tools.ietf.org/html/rfc7519#section-4.1.4) value for any token
  # signed by the old private key before this method was called.
  def expire_private_key,
    do: GenServer.cast(__MODULE__, :expire_private_key)

  # Generate a new keypair along with the key ID (kid)
  @spec generate_keypair() :: {:ok, JOSE.JWK.t(), JOSE.JWK.t(), String.t()}
  def generate_keypair() do
    # Choose an appropriate signing algorithm for your security needs.
    private_key = JOSE.JWK.generate_key({:okp, :Ed25519})

    # Generate a kid by using the key's thumbprint
    # https://tools.ietf.org/html/draft-ietf-jose-jwk-thumbprint-08#section-1
    kid = JOSE.JWK.thumbprint(private_key)

    # Update the private key to contain the "kid"
    private_key = JOSE.JWK.merge(private_key, %{"kid" => kid})

    # Create a public key based on the private key. It will carry the same "kid"
    public_key = JOSE.JWK.to_public(private_key)

    {:ok, private_key, public_key, kid}
  end

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def init(_opts) do
    {:ok, %{private_key: nil, public_keys: %{}}}
  end

  # Callbacks

  def handle_cast(:expire_private_key, state),
    do: {:noreply, %{state | private_key: nil}}

  # Generate a new signing key if one does not already exist
  def handle_call(:fetch_private_key, _from, %{private_key: nil, public_keys: key_list}) do
    {:ok, private_key, public_key, kid} = generate_keypair()

    {:reply, private_key,
     %{
       private_key: private_key,
       public_keys: Map.put(key_list, kid, public_key)
     }}
  end

  def handle_call(:fetch_private_key, _from, %{private_key: private_key} = state),
    do: {:reply, private_key, state}

  def handle_call({:fetch_public_key, kid}, _from, %{public_keys: public_keys} = state),
    do: {:reply, Map.fetch(public_keys, kid), state}

  def handle_call(:fetch_public_keys, _from, %{public_keys: public_keys} = state),
    do: {:reply, Map.values(public_keys), state}
end
```

Update Guardian's configuration to use the custom KeyServer:

```elixir
## config/config.exs

config :my_app, MyApp.Guardian,
  issuer: "myapp",
  allowed_algos: ["Ed25519"],
  secret_fetcher: MyApp.Guardian.KeyServer
```

Start the KeyServer in the supervision tree so it can serve requests:

```elixir
## lib/my_app/application.ex

def start(_type, _args) do
  # List all child processes to be supervised
  children =
  [
    MyAppWeb.Endpoint,
    MyApp.Guardian.KeyServer
  ]

  # See https://hexdocs.pm/elixir/Supervisor.html
  # for other strategies and supported options
  opts = [strategy: :one_for_one, name: MyApp.Supervisor]
  Supervisor.start_link(children, opts)
end
```

## Copyright and License

Copyright (c) 2015 Daniel Neighman

This library is MIT licensed. See the [LICENSE](https://github.com/ueberauth/guardian/blob/master/LICENSE) for details.
