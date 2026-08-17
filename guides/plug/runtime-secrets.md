# Runtime secrets

Some applications cannot know the verifying secret at compile time. The common case is
multitenancy: tokens are issued and signed by a third party, and each tenant has its own public
key. The key to verify with is only known once the request has been resolved to a tenant.

The verify plugs forward any unrecognized option to `Guardian.decode_and_verify/4`, and from there
to the token module. For `Guardian.Token.Jwt`, a `:secret` option overrides the implementation
module's `:secret_key` configuration:

```elixir
plug Guardian.Plug.VerifyHeader, secret: "a-secret-for-this-endpoint"
```

That is enough when the secret is static. It is not enough for multitenancy, because plug options
are built once by `init/1` at compile time and cannot see the connection.

## Selecting a secret per request

Plugs compose, so wrap the Guardian plug and merge the secret into its options at call time:

```elixir
defmodule MyAppWeb.VerifyHeader do
  @behaviour Plug

  alias Guardian.Plug.VerifyHeader

  @impl Plug
  def init(opts), do: VerifyHeader.init(opts)

  @impl Plug
  def call(conn, opts) do
    VerifyHeader.call(conn, Keyword.put(opts, :secret, verifying_secret(conn)))
  end

  defp verifying_secret(conn) do
    case JOSE.JWK.from_pem(conn.assigns.current_tenant.public_key) do
      %JOSE.JWK{} = jwk -> jwk
      _ -> nil
    end
  end
end
```

Call `VerifyHeader.init/1` from your own `init/1`. It compiles the `:scheme` option into the
regular expression the plug uses to strip the `Bearer` prefix, and skipping it changes how tokens
are matched.

Use your plug wherever you would have used the Guardian one, downstream of whatever assigns the
tenant:

```elixir
pipeline :api_auth do
  plug MyAppWeb.LoadTenant
  plug MyAppWeb.VerifyHeader
  plug Guardian.Plug.EnsureAuthenticated
end
```

## Do not let the secret be nil

A `nil` secret is not treated as an error. `Guardian.Token.Jwt` falls back to the implementation
module's `:secret_key` configuration whenever the resolved `:secret` is `nil`, so a tenant lookup
that quietly fails will verify tokens against your application-wide secret instead of the tenant's
key. If both an application-wide secret and third-party tenant keys are in play, that is a tenant
isolation failure rather than a rejected request.

Fail closed instead of passing `nil` down:

```elixir
import Plug.Conn

@impl Plug
def call(conn, opts) do
  case verifying_secret(conn) do
    nil -> conn |> resp(401, "") |> halt()
    secret -> VerifyHeader.call(conn, Keyword.put(opts, :secret, secret))
  end
end
```

Routing the rejection through the pipeline's error handler works too:

```elixir
nil ->
  conn
  |> Guardian.Plug.Pipeline.fetch_error_handler!(opts)
  |> apply(:auth_error, [conn, {:invalid_token, :secret_not_found}, opts])
  |> halt()
```

## Choosing a secret from the token headers

If the secret depends on the token rather than on the connection (a `kid` header pointing into a
JWKS, for example), you do not need a plug at all. Implement a
`Guardian.Token.Jwt.SecretFetcher` and configure it on your implementation module:

```elixir
defmodule MyApp.SecretFetcher do
  use Guardian.Token.Jwt.SecretFetcher

  def fetch_verifying_secret(_mod, %{"kid" => kid}, _opts) do
    case MyApp.JWKS.fetch(kid) do
      {:ok, jwk} -> {:ok, jwk}
      :error -> {:error, :secret_not_found}
    end
  end

  def fetch_verifying_secret(_mod, _headers, _opts), do: {:error, :secret_not_found}
end
```

```elixir
config :my_app, MyApp.Guardian, secret_fetcher: MyApp.SecretFetcher
```

The two approaches compose. A secret fetcher receives the options the plug was called with, so a
wrapper plug can pass tenant information through to it:

```elixir
def call(conn, opts) do
  VerifyHeader.call(conn, Keyword.put(opts, :tenant, conn.assigns.current_tenant))
end
```

```elixir
def fetch_verifying_secret(_mod, %{"kid" => kid}, opts) do
  opts
  |> Keyword.fetch!(:tenant)
  |> MyApp.JWKS.fetch(kid)
end
```
