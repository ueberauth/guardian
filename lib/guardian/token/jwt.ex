defmodule Guardian.Token.Jwt do
  @moduledoc """
  Deals with things JWT. This module should not be used directly.

  It is intended to be used by Guardian on behalf of your implementation
  as it's token module.

  Token types are encoded in the `typ` field.

  ### Configuration

  Configuration should be added to the implementation module
  in either the configuration file or as options to `use Guardian`

  #### Required

  * `issuer` - The issuer of the token. Your application name/id
  * `secret_key` - The secret key to use for the implementation module. This
    may be any resolvable value for `Guardian.Config`

  #### Optional

  * `token_verify_module` - default `Guardian.Token.Jwt.Verify`. The module that verifies the claims
  * `allowed_algos` - The allowed algos to use for encoding and decoding. See
    JOSE for available. Default ["HS512"]
  * `ttl` - The default time to live for all tokens. See the type in
    Guardian.ttl. The default by `Guardian.Token.JWT` is `{4, :weeks}`
  * `token_ttl` a map of `token_type` to `ttl`. Set specific ttls for specific types of tokens
  * `allowed_drift` The drift that is allowed when decoding/verifying a token in milli seconds
  * `verify_issuer` Verify that the token was issued by the configured issuer. Default false
  * `secret_fetcher` A module used to fetch the secret. Default: `Guardian.Token.Jwt.SecretFetcher`

  Options:

  These options are available to encoding and decoding:

  * `secret` The secret key to use for signing
  * `headers` The Jose headers that should be used
  * `allowed_algos` - A list of allowable algos
  * `token_type` - Override the default token type. The default is "access"
  * `ttl` - The time to live. See `Guardian.Token.ttl` type

  #### Example

  ```elixir
  # encode a simple token
  {:ok, token, claims} =
    MyApp.Tokens.encode_and_sign(resource)

  # encode a token with custom claims
  {:ok, token, claims} =
    MyApp.Tokens.encode_and_sign(resource, %{some: "claim"})

  # encode a token with a custom type
  {:ok, token, claims} =
    MyApp.Tokens.encode_and_sign(resource, %{}, token_type: "refresh")

  # encode a token with custom options
  {:ok, token, claims} =
    MyApp.Tokens.encode_and_sign(
      resource,
      %{},
      secret: {MyModule, :get_my_secret, ["some", "args"]},
      ttl: {4, :weeks},
      token_type: "refresh"
    )

  # decode a token
  {:ok, claims} =
    MyApp.Tokens.decode_and_verify(token)

  # decode a token and check literal claims
  {:ok, claims} =
    MyApp.Tokens.decode_and_verify(token, %{"typ" => "refresh"})

  # decode a token and check literal claims with options
  {:ok, claims} =
    MyApp.Tokens.decode_and_verify(token,
      %{"typ" => "refresh"}, secret: {MyModule, :get_my_secret, ["some", "args"]})

  # exchange a token
  {:ok, {old_token, old_claims}, {new_token, new_claims}} =
    MyApp.Tokens.exchange(old_token, ["access", "refresh"], "access")

  # exchange a token with options
  {:ok, {old_token, old_claims}, {new_token, new_claims}} =
    MyApp.Tokens.exchange(old_token,
      ["access", "refresh"],
      "access" secret: {MyModule, :get_my_secret, ["some", "args"]}, ttl: {1, :hour})

  # refresh a token using defaults
  {:ok, {old_token, old_claims}, {new_token, new_claims}} = MyApp.Tokens.refresh(old_token)

  # refresh a token using options
  {:ok, {old_token, old_claims}, {new_token, new_claims}} =
    MyApp.Tokens.refresh(old_token, ttl: {1, :week}, secret: {MyMod, :get_secret, ["some", "args"})

  ```

  ### Token verify module

  The token verify module by default is `Guardian.Token.Jwt.Verify`.

  This module implements the `Guardian.Token.Verify` behaviour.
  To customize your token validation you have 2 options.

  1. Implement the `verify_claims` callback on your implementation
  2. `use Guardian.Token.Verify` in your own module and use that.

  To create your own verify module use `Guardian.Token.Verify` and configure
  your implementation to use it either through config files or when you setup
  your implementation.

  ```elixir
  defmodule MyApp.Tokens do
    use Guardian, otp_app: :my_app,
                  token_verify_module: MyVerifyModule
    # ... snip
  end
  ```

  ### SecretFetcher

  When you need dynamic secret verification, you should use a custom
  `Guardian.Token.Jwt.SecretFetcher` module.

  This will allow you to use the header values to determine dynamically the
  key that should be used.

  ```elixir
  defmodule MyCustomSecretFetcher do
    use Guardian.Token.Jwt.SecretFetcher

    def fetch_signing_secret(impl_module, opts) do
      # fetch the secret for signing
    end

    def fetch_verifying_secret(impl_module, token_headers, opts) do
      # fetch the secret for verifying the token
    end
  end
  ```

  If the signing secret contains a "kid" (https://tools.ietf.org/html/rfc7515#section-4.1.4)
  it will be passed along to the signature to provide a hint about which secret was used.

  This can be useful for specifying which public key to use during verification if you're using
  a public/private key rotation strategy.

  An example implementation of this can be found here: [https://gist.github.com/mpinkston/469009001b694d3ca162894d74c9bfe3](https://gist.github.com/mpinkston/469009001b694d3ca162894d74c9bfe3)

  """

  @behaviour Guardian.Token

  alias Guardian.Config
  alias Guardian.Token.Jwt.SecretFetcher.SecretFetcherDefaultImpl
  alias Guardian.Token.Jwt.Verify

  alias JOSE.JWK
  alias JOSE.JWS
  alias JOSE.JWT

  import Guardian, only: [stringify_keys: 1, ttl_to_seconds: 1]

  @default_algos ["HS512"]
  @default_token_type "access"
  @type_key "typ"
  @default_ttl {4, :weeks}

  defmodule SecretFetcher do
    @moduledoc """
    Provides a behaviour that specifies how to fetch the secret for the token.

    `use Guardian.Token.JWT.SecretFetcher` to provide default implementations of each function.
    """

    @doc """
    fetch_signing_secret fetches the secret to sign.
    """
    @callback fetch_signing_secret(module, opts :: Guardian.options()) :: {:ok, term} | {:error, :secret_not_found}

    @doc """
    Fetches the secret to verify a token.

    It is provided with the tokens headers in order to lookup the secret.
    """
    @callback fetch_verifying_secret(module, token_headers :: map, opts :: Guardian.options()) ::
                {:ok, term} | {:error, :secret_not_found}

    defmacro __using__(_opts \\ []) do
      quote do
        alias Guardian.Token.Jwt.SecretFetcher.SecretFetcherDefaultImpl

        def fetch_signing_secret(mod, opts) do
          SecretFetcherDefaultImpl.fetch_signing_secret(mod, opts)
        end

        def fetch_verifying_secret(mod, token_headers, opts) do
          SecretFetcherDefaultImpl.fetch_verifying_secret(mod, token_headers, opts)
        end

        defoverridable fetch_signing_secret: 2, fetch_verifying_secret: 3
      end
    end
  end

  defmodule SecretFetcher.SecretFetcherDefaultImpl do
    @moduledoc false
    use Guardian.Token.Jwt.SecretFetcher

    def fetch_signing_secret(mod, opts) do
      secret = Keyword.get(opts, :secret)
      secret = Config.resolve_value(secret) || apply(mod, :config, [:secret_key])

      case secret do
        nil -> {:error, :secret_not_found}
        val -> {:ok, val}
      end
    end

    def fetch_verifying_secret(mod, _token_headers, opts) do
      secret = Keyword.get(opts, :secret)
      secret = Config.resolve_value(secret) || mod.config(:secret_key)

      case secret do
        nil -> {:error, :secret_not_found}
        val -> {:ok, val}
      end
    end
  end

  @doc """
  Inspect the JWT without any validation or signature checking.

  Return an map with keys: `headers` and `claims`.
  """
  def peek(_mod, nil), do: nil

  def peek(_mod, token) do
    %{headers: JWT.peek_protected(token).fields, claims: JWT.peek_payload(token).fields}
  end

  @doc """
  Generate unique token id.
  """
  def token_id, do: Guardian.UUID.generate()

  @doc """
  Create a token. Uses the claims, encodes and signs the token.

  The signing secret will be found first from the options.
  If not specified the secret key from the configuration will be used.

  Configuration:

  * `secret_key` The secret key to use for signing

  Options:

  * `secret` The secret key to use for signing
  * `headers` The Jose headers that should be used
  * `allowed_algos`

  The secret may be in the form of any resolved value from `Guardian.Config`.
  """
  def create_token(mod, claims, options \\ []) do
    with {:ok, secret_fetcher} <- fetch_secret_fetcher(mod),
         {:ok, secret} <- secret_fetcher.fetch_signing_secret(mod, options) do
      jose_jwk = jose_jwk(secret)

      {_, token} =
        jose_jwk
        |> JWT.sign(jose_jws(mod, jose_jwk, options), claims)
        |> JWS.compact()

      {:ok, token}
    end
  end

  @doc """
  Builds the default claims for all JWT tokens.

  Note:

  * `aud` is set to the configured `issuer` unless `aud` is set

  Options:

  Options may override the defaults found in the configuration.

  * `token_type` - Override the default token type
  * `ttl` - The time to live. See `Guardian.Token.ttl` type
  """
  # credo:disable-for-next-line /\.Warning\./
  def build_claims(mod, _resource, sub, claims \\ %{}, options \\ []) do
    claims =
      claims
      |> stringify_keys()
      |> set_jti()
      |> set_iat()
      |> set_iss(mod, options)
      |> set_aud(mod, options)
      |> set_type(mod, options)
      |> set_sub(mod, sub, options)
      |> set_ttl(mod, options)
      |> set_auth_time(mod, options)

    {:ok, claims}
  end

  @doc """
  Decodes the token and validates the signature.

  Options:

  * `secret` - Override the configured secret. `Guardian.Config.config_value` is valid
  * `allowed_algos` - A list of allowable algos
  """
  def decode_token(mod, token, options \\ []) do
    with {:ok, secret_fetcher} <- fetch_secret_fetcher(mod),
         %{headers: headers} <- peek(mod, token),
         {:ok, raw_secret} <- secret_fetcher.fetch_verifying_secret(mod, headers, options),
         secret <- jose_jwk(raw_secret),
         algos = fetch_allowed_algos(mod, options) do
      verify_result = JWT.verify_strict(secret, algos, token)

      case verify_result do
        {true, jose_jwt, _} -> {:ok, jose_jwt.fields}
        {false, _, _} -> {:error, :invalid_token}
      end
    end
  end

  @doc """
  Verifies the claims.

  Options:

  * `token_verify_module` - the module to use to verify the claims. Default
    `Guardian.Token.Jwt.Verify`
  """
  def verify_claims(mod, claims, options) do
    result =
      mod
      |> apply(:config, [:token_verify_module, Verify])
      |> apply(:verify_claims, [mod, claims, options])

    case result do
      {:ok, claims} -> apply(mod, :verify_claims, [claims, options])
      err -> err
    end
  end

  @doc """
  Revoking a JWT by default does not do anything.

  You'll need to track the token in storage in some way
  and revoke in your implementation callbacks.

  See `GuardianDb` for an example.
  """
  def revoke(_mod, claims, _token, _options), do: {:ok, claims}

  @doc """
  Refresh the token

  Options:

  * `secret` - Override the configured secret. `Guardian.Config.config_value` is valid
  * `allowed_algos` - A list of allowable algos
  * `ttl` - The time to live. See `Guardian.Token.ttl` type
  """
  def refresh(mod, old_token, options) do
    with {:ok, old_claims} <- apply(mod, :decode_and_verify, [old_token, %{}, options]),
         {:ok, claims} <- refresh_claims(mod, old_claims, options),
         {:ok, token} <- create_token(mod, claims, options) do
      {:ok, {old_token, old_claims}, {token, claims}}
    else
      {:error, _} = err -> err
      err -> {:error, err}
    end
  end

  @doc """
  Exchange a token of one type to another.

  Type is encoded in the `typ` field.

  Options:

  * `secret` - Override the configured secret. `Guardian.Config.config_value` is valid
  * `allowed_algos` - A list of allowable algos
  * `ttl` - The time to live. See `Guardian.Token.ttl` type
  """
  def exchange(mod, old_token, from_type, to_type, options) do
    with {:ok, old_claims} <- apply(mod, :decode_and_verify, [old_token, %{}, options]),
         {:ok, claims} <- exchange_claims(mod, old_claims, from_type, to_type, options),
         {:ok, token} <- create_token(mod, claims, options) do
      {:ok, {old_token, old_claims}, {token, claims}}
    else
      {:error, _} = err -> err
      err -> {:error, err}
    end
  end

  # If the JWK includes a "kid" add this to the signature to provide a hint
  # about which key was used.
  # See https://tools.ietf.org/html/rfc7515#section-4.1.4
  defp jose_jws(mod, %JWK{fields: %{"kid" => kid}}, opts) do
    header = %{"kid" => kid}
    opts = Keyword.update(opts, :headers, header, &Map.merge(&1, header))
    jose_jws(mod, opts)
  end

  defp jose_jws(mod, _, opts), do: jose_jws(mod, opts)

  defp jose_jws(mod, opts) do
    algos = fetch_allowed_algos(mod, opts) || @default_algos
    headers = Keyword.get(opts, :headers, %{})
    Map.merge(%{"alg" => hd(algos)}, headers)
  end

  defp jose_jwk(%JWK{} = the_secret), do: the_secret
  defp jose_jwk(the_secret) when is_binary(the_secret), do: JWK.from_oct(the_secret)
  defp jose_jwk(the_secret) when is_map(the_secret), do: JWK.from_map(the_secret)
  defp jose_jwk(value), do: Config.resolve_value(value)

  defp fetch_allowed_algos(mod, opts) do
    opts
    |> Keyword.get(:allowed_algos)
    |> Config.resolve_value() || apply(mod, :config, [:allowed_algos, @default_algos])
  end

  defp set_type(%{"typ" => typ} = claims, _mod, _opts) when not is_nil(typ), do: claims

  defp set_type(claims, mod, opts) do
    defaults = apply(mod, :default_token_type, [])
    typ = Keyword.get(opts, :token_type, defaults)
    Map.put(claims, @type_key, to_string(typ || @default_token_type))
  end

  defp set_sub(claims, _mod, subject, _opts), do: Map.put(claims, "sub", subject)

  defp set_iat(claims) do
    ts = Guardian.timestamp()
    claims |> Map.put("iat", ts) |> Map.put("nbf", ts - 1)
  end

  defp set_ttl(%{"exp" => exp} = claims, _mod, _opts) when not is_nil(exp), do: claims

  defp set_ttl(claims, mod, opts) do
    ttl = Keyword.get(opts, :ttl)

    if ttl do
      set_ttl(claims, ttl)
    else
      token_typ = claims |> Map.fetch!("typ") |> to_string()
      token_ttl = apply(mod, :config, [:token_ttl, %{}])
      fallback_ttl = apply(mod, :config, [:ttl, @default_ttl])

      ttl = Map.get(token_ttl, token_typ, fallback_ttl)
      set_ttl(claims, ttl)
    end
  end

  defp set_ttl(the_claims, {num, period}) when is_binary(num),
    do: set_ttl(the_claims, {String.to_integer(num), period})

  defp set_ttl(the_claims, {num, period}) when is_binary(period),
    do: set_ttl(the_claims, {num, String.to_existing_atom(period)})

  defp set_ttl(%{"iat" => iat_v} = the_claims, requested_ttl),
    do: assign_exp_from_ttl(the_claims, {iat_v, requested_ttl})

  # catch all for when the issued at iat is not yet set
  defp set_ttl(claims, requested_ttl), do: claims |> set_iat() |> set_ttl(requested_ttl)

  defp set_auth_time(%{"auth_time" => auth_time} = claims, _mod, _opts) when not is_nil(auth_time), do: claims

  defp set_auth_time(%{"iat" => iat} = claims, mod, opts) do
    set_auth_time =
      if opts[:auth_time] !== nil do
        opts[:auth_time]
      else
        case mod.config(:auth_time) do
          nil -> opts[:max_age] || mod.config(:max_age)
          auth_time -> auth_time
        end
      end

    if set_auth_time do
      Map.put(claims, "auth_time", iat)
    else
      claims
    end
  end

  defp assign_exp_from_ttl(the_claims, {iat_v, ttl}),
    do: Map.put(the_claims, "exp", iat_v + ttl_to_seconds(ttl))

  defp set_iss(claims, mod, _opts) do
    issuer = mod |> apply(:config, [:issuer]) |> to_string()
    Map.put(claims, "iss", issuer)
  end

  defp set_aud(%{"aud" => aud} = claims, _mod, _opts) when not is_nil(aud), do: claims

  defp set_aud(claims, mod, _opts) do
    issuer = mod |> apply(:config, [:issuer]) |> to_string()
    Map.put(claims, "aud", issuer)
  end

  defp set_jti(claims), do: Map.put(claims, "jti", token_id())

  defp refresh_claims(mod, claims, options), do: {:ok, reset_claims(mod, claims, options)}

  defp exchange_claims(mod, old_claims, from_type, to_type, options) when is_list(from_type) do
    from_type = Enum.map(from_type, &to_string(&1))

    if Enum.member?(from_type, old_claims["typ"]) do
      exchange_claims(mod, old_claims, old_claims["typ"], to_type, options)
    else
      {:error, :incorrect_token_type}
    end
  end

  defp exchange_claims(mod, old_claims, from_type, to_type, options) do
    if old_claims["typ"] == to_string(from_type) do
      new_type = to_string(to_type)
      # set the type first because the ttl can depend on the type
      claims = Map.put(old_claims, "typ", new_type)
      claims = reset_claims(mod, claims, options)
      {:ok, claims}
    else
      {:error, :incorrect_token_type}
    end
  end

  defp reset_claims(mod, claims, options) do
    claims
    |> Map.drop(["jti", "iss", "iat", "nbf", "exp"])
    |> set_jti()
    |> set_iat()
    |> set_iss(mod, options)
    |> set_ttl(mod, options)
  end

  defp fetch_secret_fetcher(mod) do
    {:ok, mod.config(:secret_fetcher, SecretFetcherDefaultImpl)}
  end
end
