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

That is enough when the secret is static. Plug options are built once by `init/1` at compile time,
so a literal value cannot depend on the request.

## Selecting a secret per request

Give `:secret` a one argument function. The verify plugs call it with the connection and use what
it returns:

```elixir
plug MyAppWeb.LoadTenant
plug Guardian.Plug.VerifyHeader, secret: &MyApp.Secrets.for_conn/1
```

```elixir
defmodule MyApp.Secrets do
  def for_conn(conn) do
    case JOSE.JWK.from_pem(conn.assigns.current_tenant.public_key) do
      %JOSE.JWK{} = jwk -> jwk
      _ -> nil
    end
  end
end
```

Use a remote capture such as `&MyApp.Secrets.for_conn/1`. `Plug.Builder` and Phoenix router
pipelines call `init/1` at compile time and inline the result, and an anonymous function cannot be
inlined. Writing `secret: fn conn -> ... end` or `secret: & &1.assigns.tenant.key` in a `plug`
line fails to compile with `cannot escape #Function<...>`. Both forms are fine when you call
`VerifyHeader.call/2` yourself, or under `use Plug.Builder, init_mode: :runtime`.

This works on `Guardian.Plug.VerifyHeader`, `Guardian.Plug.VerifySession` and
`Guardian.Plug.VerifyCookie`. Place it downstream of whatever resolves the tenant:

```elixir
pipeline :api_auth do
  plug MyAppWeb.LoadTenant
  plug Guardian.Plug.VerifyHeader, secret: &MyApp.Secrets.for_conn/1
  plug Guardian.Plug.EnsureAuthenticated
end
```

### A nil secret fails closed

Returning `nil` rejects the request with `{:invalid_token, :secret_not_found}`. It does **not**
fall back to the implementation module's `:secret_key`, so a tenant lookup that quietly fails
cannot end up verifying tokens against your application wide secret.

Guardian versions before this behaviour change did fall back. If you were selecting secrets at
runtime with a wrapper plug, check whether your code relied on that fallback for requests with no
tenant.

## Other option forms

`:secret` also accepts a `{module, function, args}` tuple, resolved by
`Guardian.Config.resolve_value/1`:

```elixir
plug Guardian.Plug.VerifyHeader, secret: {MyApp.Vault, :fetch, ["api-signing-key"]}
```

The arguments are fixed at compile time and the connection is not passed, so this suits a secret
read from a vault or environment rather than one that varies per request. Use the one argument
function form when the choice depends on the connection.

## Choosing a secret from the token headers

If the secret depends on the token rather than on the connection (a `kid` header pointing into a
JWKS, for example), you do not need a plug option at all. Implement a
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

Unlike the plug option, a secret fetcher also covers token creation and applies everywhere the
implementation module is used, not only behind a plug.

## Which one to reach for

The plug option sees the connection. The secret fetcher sees the token headers. Pick whichever
holds the information your lookup needs, and prefer the plug option when either would work, since
it keeps the choice visible at the pipeline.

If a lookup genuinely needs both, note that a secret fetcher also receives the options the plug was
called with, so connection derived context can be handed to it through any option name.

Options other than `:secret` still have no connection aware form. Varying those per request means
wrapping the verify plug in your own, in which case delegate to the wrapped plug's `init/1`:
`VerifyHeader.init/1` compiles the `:scheme` option into the regular expression used to strip the
`Bearer` prefix, and skipping it changes how tokens are matched.
