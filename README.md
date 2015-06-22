Guardian
========

An authentication framework for use with Elixir applications.

Guardian is based on similar ideas to Warden and Omniauth but is re-imagined
for modern systems where Elixir manages the authentication requrements.

Guardian remains a functional system. It integrates with Plug, but can be used
outside of it. If you're implementing a TCP/UDP protocol directly, or want to
utilize your authentication via channels, Guardian is your friend.

The core currency of authentication in Guardian is JWT. You can use the JWT to
authenticate web endpoints, channels, and TCP sockets.

## Installation

Guardian relies on [Joken](https://github.com/bryanjos/joken). You'll need to
install and configure Joken for your application.

Add Guardian to your application

mix.deps

```elixir
defp deps do
  [
    # ...
    {:guardian, "~> 0.1.0"}
    # ...
  ]
end
```

config.exs

```elixir
config :joken,
  secret_key: <secret key>,
  json_module: Guardian.JWT

config :guardian, Guardian,
  issuer: "MyApp",
  ttl: { 30, :days },
  verify_issuer: true,
  secret_key: <guardian secret key>,
  serializer: MyApp.GuardianSerializer
```

## Serializer

The serializer knows how to encode and decode your resource into and out of the
token. A simple serializer:

```elixir
defmodule MyApp do
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

### Guardian.Plug.VerifyAuthorization

Looks for a token in the Authorization header. Useful for apis.
If one is not found, this does nothing.

### Guardian.Plug.EnsureSession

Looks for a previously verified token. If one is found, continues, otherwise it
will call the `:on_failure` function.

When you ensure a session, you must declare an error handler. This can be done
as part of a pipeline or inside a pheonix controller.

```elixir
defmodule MyApp.MyController do
  use MyApp.Web, :controller

  plug Guardian.Plug.EnsureSession, on_failure: { MyApp.MyController, :unauthenticated }
end
```

The failure function must receive the connection, and the connection params.

### Pipelines

These plugs can be used to construct pipelines in Phoenix.

```elixir
pipeline :browser_session do
  plug Guardian.Plug.VerifySession
  plug Guardian.Plug.LoadResource
end

pipeline :api do
  plug :accepts, ["json"]
  plug Guardian.Plug.VerifyAuthorization
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

From here, you can either EnsureSession in your pipeline, or on a per-controller basis.

```elixir
defmodule MyApp.MyController do
  use MyApp.Web, :controller

  plug Guardian.Plug.EnsureSession, on_failure: { MyApp.MyHandler, :unauthenticated }
end
```

## Sign in and Sign out

It's up to you how you verify the claims to encode into the token Guardian uses.
As an example, here's the important parts of a SessionController

```elixir
defmodule MyApp.SessionController do
  use MyApp.Web, :controller

  alias MyApp.User
  alias MyApp.UserQuery

  plug :scrub_params, "user" when action in [:create]
  plug :action

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
Guardian.Plug.sign_in(conn, user, :csrf) # sign in using a csrf signed token

Guardian.Plug.sign_in(conn, user, :token, claims)  # give some claims to use for the token jwt

Guardian.Plug.sign_in(conn, user, :token, %{ key: :secret })  # create a token in the :secret location
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
have run the VerifySession/Authorization for token and claim access, and LoadResource to access the resource.

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
{ :ok, jwt, encoded_claims } = Guardian.mint(resource, <token_type>, claims_map)
```

This will give you a minted JWT to use with the claims ready to go.
The token type is encoded into the JWT as the 'aud' field and is intended to be
used as the _type_ of token.

CSRF token protection can be put into the JWT that is produced when you mint.
When you're inside a plug, you can simply call mint with the type

```elixir
{ :ok, jwt, full_claims } = Guardian.Plug.sign_in(resource, :csrf)
```

If you are not inside plug, you'll need to supply the csrf token to use.

```elixir
{ :ok, jwt, full_claims } = Guardian.mint(resource, :csrf, %{ csrf: "some token" })
```

Currently suggested token types are:

* `"token"` - Use for API or CORS access. These are basic tokens with no csrf checking.
* `"csrf"` - Use for browser based access. These require a the CSRF token signed into the token to match the CSRF token for the request

There is a todo on Guardian to integrate signed csrf for a "csrf" token type and
perform csrf checking.

You can also customize the claims you're asserting.

```elixir
claims = Guardian.Claims.app_claims
         |> Dict.put(:some_claim, some_value)
         |> Guardian.Claims.ttl({3, :days})

{ :ok, jwt, full_claims } = Guardian.mint(resource, :token, claims)
```

To verify the token:

```elixir
case Guardian.verify(jwt) do
  { :ok, claims } -> do_things_with_claims(claims)
  { :error, reason } -> do_things_with_an_error(reason)
end
```

Accessing the resource from a set of claims:

```elixir
case Guardian.serializer.from_token(claims) do
  { :ok, resource } -> do_things_with_resource(resource)
  { :error, reason } -> do_things_without_a_resource(reason)
end
```

### Phoenix Channels

Guardian uses JWTs to make the integration of authentication management as
seamless as possible. Channel integration is part of that.

```elixir
defmodule MyApp.UsersChannel do
  use Phoenix.Channel
  use Guardian.Channel

  def join(_room, %{ claims: claims, resource: resource }, socket) do
    { :ok, %{ message: "Joined" }, socket }
  end

  def join(room, _, socket) do
    { :error,  :authentication_required }
  end

  def handle_in("ping", _payload, socket) do
    user = Guardian.Channel.current_resource(socket)
    broadcast socket, "pong", %{ message: "pong", from: user.email }
    { :noreply, socket }
  end
end
```

Guardian picks up on joins that have been made and automatically verifies the
token and makes available the claims and resource making the request.

For non csrf protected tokens, the javascript to join a channel is simple.

```javascript
let socket = new Socket("/ws");
socket.connect();
let guardianToken = jQuery('meta[name="guardian_token"]').attr('content');
let chan = socket.chan("pings", { guardian_token: guardianToken });
```

To add csrf protection, use the csrf token type when signing in, then pass up
the token when joining.

```javascript
let socket = new Socket("/ws");
socket.connect();
let guardianToken = jQuery('meta[name="guardian_token"]').attr('content');
let csrfToken = jQuery('meta[name="csrf_token"]').attr('content');
let chan = socket.chan("pings", { guardian_token: guardianToken, csrf_token: csrfToken });
```

How to get the tokens onto the page?

```eex
<meta name='csrf_token' content='<%= Plug.CSRFProtection.get_csrf_token %>'>
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
- [x] Sevice2Service credentials. That is, pass the authentication results through many downstream requests.
- [x] Create a "csrf" token type that ensures that CSRF protection is included
- [x] Integration with Phoenix channels
- [ ] Integrated permission sets
- [ ] Hooks into the authentication cycle
- [ ] Flexible strategy based authentication
- [ ] Two-factor authentication
- [ ] Single sign-in
- [ ] Device specific signing
