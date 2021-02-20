defmodule Guardian do
  @moduledoc ~S"""
  Guardian provides a singular interface for authentication in Elixir applications
  that is `token` based.

  Tokens should be:

  * tamper proof
  * include a payload (claims)

  JWT tokens (the default) fit this description.

  When using Guardian, you'll need an implementation module.

  ```elixir
  defmodule MyApp.Guardian do
    use Guardian, otp_app: :my_app

    def subject_for_token(resource, _claims), do: {:ok, to_string(resource.id)}
    def resource_from_claims(claims) do
      find_me_a_resource(claims["sub"]) # {:ok, resource} or {:error, reason}
    end
  end
  ```

  This module is what you will use to interact with tokens in your application.

  When you `use` Guardian, the `:otp_app` option is required.
  Any other option provided will be merged with the configuration in the config
  files.

  The Guardian module contains some generated functions and some callbacks.

  ## Generated functions

  ### `default_token_type()`

  Overridable.

  Provides the default token type for the token - `"access"`

  Token types allow a developer to mark a token as having a particular purpose.
  Different types of tokens can then be used specifically in your app.

  Types may include (but are not limited to):

  * `"access"`
  * `"refresh"`

  Access tokens should be short lived and are used to access resources on your API.
  Refresh tokens should be longer lived and whose only purpose is to exchange
  for a shorter lived access token.

  To specify the type of token, use the `:token_type` option in
  the `encode_and_sign` function.

  Token type is encoded into the token in the `"typ"` field.

  Return - a string.

  ### `peek(token)`

  Inspect a tokens payload. Note that this function does no verification.

  Return - a map including the `:claims` key.

  ### `config()`, `config(key, default \\ nil)`

  Without argument `config` will return the full configuration Keyword list.

  When given a `key` and optionally a default, `config` will fetch a resolved value
  contained in the key.

  See `Guardian.Config.resolve_value/1`

  ### `encode_and_sign(resource, claims \\ %{}, opts \\ [])`

  Creates a signed token.

  Arguments:

  * `resource` - The resource to represent in the token (i.e. the user)
  * `claims` - Any custom claims that you want to use in your token
  * `opts` - Options for the token module and callbacks

  For more information on options see the documentation for your token module.

  ```elixir
  # Provide a token using the defaults including the default_token_type
  {:ok, token, full_claims} = MyApp.Guardian.encode_and_sign(user)

  # Provide a token including custom claims
  {:ok, token, full_claims} = MyApp.Guardian.encode_and_sign(user, %{some: "claim"})

  # Provide a token including custom claims and a different token type/ttl
  {:ok, token, full_claims} =
    MyApp.Guardian.encode_and_sign(user, %{some: "claim"}, token_type: "refresh", ttl: {4, :weeks})
  ```

  The `encode_and_sign` function calls a number of callbacks on
  your implementation module. See `Guardian.encode_and_sign/4`

  ### `decode_and_verify(token, claims_to_check \\ %{}, opts \\ [])`

  Decodes a token and verifies the claims are valid.

  Arguments:

  * `token` - The token to decode
  * `claims_to_check` - A map of the literal claims that should be matched. If
    any of the claims do not literally match verification fails.
  * `opts` - The options to pass to the token module and callbacks

  Callbacks:

  `decode_and_verify` calls a number of callbacks on your implementation module,
  See `Guardian.decode_and_verify/4`

  ```elixir
  # Decode and verify using the defaults
  {:ok, claims} = MyApp.Guardian.decode_and_verify(token)

  # Decode and verify with literal claims check.
  # If the claims in the token do not match those given verification will fail
  {:ok, claims} = MyApp.Guardian.decode_and_verify(token, %{match: "claim"})

  # Decode and verify with literal claims check and options.
  # Options are passed to your token module and callbacks
  {:ok, claims} = MyApp.Guardian.decode_and_verify(token, %{match: "claim"}, some: "secret")
  ```

  ### `revoke(token, opts \\ [])`

  Revoke a token.

  *Note:* this is entirely dependent on your token module and implementation
  callbacks.

  ```elixir
  {:ok, claims} = MyApp.Guardian.revoke(token, some: "option")
  ```

  ### refresh(token, opts \\ [])

  Refreshes the time on a token. This is used to re-issue a token with
  essentially the same claims but with a different expiry.

  Tokens are verified before performing the refresh to ensure
  only valid tokens may be refreshed.

  Arguments:

  * `token` - The old token to refresh
  * `opts` - Options to pass to the Implementation Module and callbacks

  Options:

  * `:ttl` - The new ttl. If not specified the default will be used.

  ```elixir
  {:ok, {old_token, old_claims}, {new_token, new_claims}} =
    MyApp.Guardian.refresh(old_token, ttl: {1, :hour})
  ```

  See `Guardian.refresh`

  ### `exchange(old_token, from_type, to_type, options)`

  Exchanges one token for another of a different type.
  Especially useful to trade in a `refresh` token for an `access` one.

  Tokens are verified before performing the exchange to ensure that
  only valid tokens may be exchanged.

  Arguments:

  * `old_token` - The existing token you wish to exchange.
  * `from_type` - The type the old token must be. Can be given a list of types.
  * `to_type` - The new type of token that you want back.
  * `options` - The options to pass to the token module and callbacks.

  Options:

  Options may be used by your token module or callbacks.

  * `ttl` - The ttl for the new token

  See `Guardian.exchange`
  """

  @type options :: Keyword.t()
  @type conditional_tuple :: {:ok, any} | {:error, any}

  @default_token_module Guardian.Token.Jwt

  @doc """
  Fetches the subject for a token for the provided resource and claims
  The subject should be a short identifier that can be used to identify
  the resource.
  """
  @callback subject_for_token(
              resource :: Guardian.Token.resource(),
              claims :: Guardian.Token.claims()
            ) :: {:ok, String.t()} | {:error, atom}

  @doc """
  Fetches the resource that is represented by claims.

  For JWT this would normally be found in the `sub` field.
  """
  @callback resource_from_claims(claims :: Guardian.Token.claims()) :: {:ok, Guardian.Token.resource()} | {:error, atom}

  @doc """
  An optional callback that allows the claims to be modified
  while they're being built.

  This is useful to hook into the encoding lifecycle.
  """
  @callback build_claims(
              claims :: Guardian.Token.claims(),
              resource :: Guardian.Token.resource(),
              opts :: options
            ) :: {:ok, Guardian.Token.claims()} | {:error, atom}

  @doc """
  An optional callback invoked after the token has been generated
  and signed.
  """
  @callback after_encode_and_sign(
              resource :: any,
              claims :: Guardian.Token.claims(),
              token :: Guardian.Token.token(),
              options :: options
            ) :: {:ok, Guardian.Token.token()} | {:error, atom}

  @doc """
  An optional callback invoked after sign in has been called.

  By returning an error the sign in will be halted.

  * Note that if you return an error, a token still may have been generated.
  """
  @callback after_sign_in(
              conn :: Plug.Conn.t(),
              resource :: any,
              token :: Guardian.Token.token(),
              claims :: Guardian.Token.claims(),
              options :: options
            ) :: {:ok, Plug.Conn.t()} | {:error, atom}

  @doc """
  An optional callback invoked before sign out has happened.
  """
  @callback before_sign_out(conn :: Plug.Conn.t(), location :: atom | nil, options :: options) ::
              {:ok, Plug.Conn.t()} | {:error, atom}

  @doc """
  An optional callback to add custom verification to claims when
  decoding a token.

  Returning `{:ok, claims}` will allow the decoding to continue.
  Returning `{:error, reason}` will stop the decoding and return the error.
  """
  @callback verify_claims(claims :: Guardian.Token.claims(), options :: options) ::
              {:ok, Guardian.Token.claims()}
              | {:error, atom}

  @doc """
  An optional callback invoked after the claims have been validated.
  """
  @callback on_verify(
              claims :: Guardian.Token.claims(),
              token :: Guardian.Token.token(),
              options :: options
            ) :: {:ok, Guardian.Token.claims()} | {:error, any}

  @doc """
  An optional callback invoked when a token is revoked.
  """
  @callback on_revoke(
              claims :: Guardian.Token.claims(),
              token :: Guardian.Token.token(),
              options :: options
            ) :: {:ok, Guardian.Token.claims()} | {:error, any}

  @doc """
  An optional callback invoked when a token is refreshed.
  """
  @callback on_refresh(
              old_token_and_claims :: {Guardian.Token.token(), Guardian.Token.claims()},
              new_token_and_claims :: {Guardian.Token.token(), Guardian.Token.claims()},
              options :: options
            ) ::
              {
                :ok,
                {Guardian.Token.token(), Guardian.Token.claims()},
                {Guardian.Token.token(), Guardian.Token.claims()}
              }
              | {:error, any}

  @doc """
  An optional callback invoked when a token is exchanged.
  """
  @callback on_exchange(
              old_token_and_claims :: {Guardian.Token.token(), Guardian.Token.claims()},
              new_token_and_claims :: {Guardian.Token.token(), Guardian.Token.claims()},
              options :: options
            ) ::
              {
                :ok,
                {Guardian.Token.token(), Guardian.Token.claims()},
                {Guardian.Token.token(), Guardian.Token.claims()}
              }
              | {:error, any}

  alias Guardian.Token.Verify

  defmodule MalformedReturnValueError do
    defexception [:message]
  end

  defmacro __using__(opts \\ []) do
    otp_app = Keyword.get(opts, :otp_app)

    # credo:disable-for-next-line Credo.Check.Refactor.LongQuoteBlocks
    quote do
      @behaviour Guardian

      if Code.ensure_loaded?(Plug) do
        __MODULE__
        |> Module.concat(:Plug)
        |> Module.create(
          quote do
            use Guardian.Plug, unquote(__MODULE__)
          end,
          Macro.Env.location(__ENV__)
        )
      end

      the_otp_app = unquote(otp_app)
      the_opts = unquote(opts)

      # Provide a way to get at the configuration during compile time
      # for other macros that may want to use them
      @config fn ->
        the_otp_app |> Application.get_env(__MODULE__, []) |> Keyword.merge(the_opts)
      end
      @config_with_key fn key ->
        @config.() |> Keyword.get(key) |> Guardian.Config.resolve_value()
      end
      @config_with_key_and_default fn key, default ->
        @config.() |> Keyword.get(key, default) |> Guardian.Config.resolve_value()
      end

      @doc """
      The default type of token for this module.
      """

      @spec default_token_type() :: String.t()
      def default_token_type, do: "access"

      @doc """
      Fetches the configuration for this module.
      """

      @spec config() :: Keyword.t()
      def config,
        do:
          unquote(otp_app)
          |> Application.get_env(__MODULE__, [])
          |> Keyword.merge(unquote(opts))

      @doc """
      Returns a resolved value of the configuration found at a key.

      See `Guardian.Config.resolve_value/1`.
      """

      @spec config(atom | String.t(), any) :: any
      def config(key, default \\ nil),
        do: config() |> Keyword.get(key, default) |> Guardian.Config.resolve_value()

      @doc """
      Provides the content of the token but without verification
      of either the claims or the signature.

      Claims will be present at the `:claims` key.

      See `Guardian.peek/2` for more information.
      """
      @spec peek(String.t()) :: map
      def peek(token) do
        Guardian.token_module(__MODULE__).peek(__MODULE__, token)
      end

      @doc """
      Encodes the claims.

      See `Guardian.encode_and_sign/4` for more information.
      """

      @spec encode_and_sign(any, Guardian.Token.claims(), Guardian.options()) ::
              {:ok, Guardian.Token.token(), Guardian.Token.claims()} | {:error, any}
      def encode_and_sign(resource, claims \\ %{}, opts \\ []),
        do: Guardian.encode_and_sign(__MODULE__, resource, claims, opts)

      @doc """
      Decodes and verifies a token using the configuration on the implementation
      module.

      See `Guardian.decode_and_verify/4`.
      """

      @spec decode_and_verify(Guardian.Token.token(), Guardian.Token.claims(), Guardian.options()) ::
              {:ok, Guardian.Token.claims()} | {:error, any}
      def decode_and_verify(token, claims_to_check \\ %{}, opts \\ []),
        do: Guardian.decode_and_verify(__MODULE__, token, claims_to_check, opts)

      @doc """
      Fetch the resource and claims directly from a token.

      See `Guardian.resource_from_token` for more information.
      """

      @spec resource_from_token(
              token :: Guardian.Token.token(),
              claims_to_check :: Guardian.Token.claims() | nil,
              opts :: Guardian.options()
            ) :: {:ok, Guardian.Token.resource(), Guardian.Token.claims()} | {:error, any}
      def resource_from_token(token, claims_to_check \\ %{}, opts \\ []),
        do: Guardian.resource_from_token(__MODULE__, token, claims_to_check, opts)

      @doc """
      Revoke a token.

      See `Guardian.revoke` for more information.
      """

      @spec revoke(Guardian.Token.token(), Guardian.options()) :: {:ok, Guardian.Token.claims()} | {:error, any}
      def revoke(token, opts \\ []), do: Guardian.revoke(__MODULE__, token, opts)

      @doc """
      Refresh a token.

      See `Guardian.refresh` for more information.
      """

      @spec refresh(Guardian.Token.token(), Guardian.options()) ::
              {
                :ok,
                {Guardian.Token.token(), Guardian.Token.claims()},
                {Guardian.Token.token(), Guardian.Token.claims()}
              }
              | {:error, any}
      def refresh(old_token, opts \\ []), do: Guardian.refresh(__MODULE__, old_token, opts)

      @doc """
      Exchanges a token of one type for another.

      See `Guardian.exchange` for more information.
      """
      @spec exchange(
              token :: Guardian.Token.token(),
              from_type :: String.t() | [String.t(), ...],
              to_type :: String.t(),
              options :: Guardian.options()
            ) ::
              {
                :ok,
                {Guardian.Token.token(), Guardian.Token.claims()},
                {Guardian.Token.token(), Guardian.Token.claims()}
              }
              | {:error, any}
      def exchange(token, from_type, to_type, opts \\ []),
        do: Guardian.exchange(__MODULE__, token, from_type, to_type, opts)

      @doc """
      If Guardian.Plug.SlidingCookie is used, this callback will be invoked to
      return the new claims, or an error (which will mean the cookie will not
      be refreshed).
      """

      @spec sliding_cookie(
              current_claims :: Guardian.Token.claims(),
              current_resource :: Guardian.Token.resource(),
              options :: Guardian.options()
            ) :: {:ok, new_claims :: Guardian.Token.claims()} | {:error, any}
      def sliding_cookie(_current_claims, _current_resource, opts \\ []),
        do: {:error, :not_implemented}

      def after_encode_and_sign(_r, _claims, token, _), do: {:ok, token}
      def after_sign_in(conn, _r, _t, _c, _o), do: {:ok, conn}
      def before_sign_out(conn, _location, _opts), do: {:ok, conn}
      def on_verify(claims, _token, _options), do: {:ok, claims}
      def on_revoke(claims, _token, _options), do: {:ok, claims}
      def on_refresh(old_stuff, new_stuff, _options), do: {:ok, old_stuff, new_stuff}
      def on_exchange(old_stuff, new_stuff, _options), do: {:ok, old_stuff, new_stuff}

      def build_claims(c, _, _), do: {:ok, c}
      def verify_claims(claims, _options), do: {:ok, claims}

      defoverridable after_encode_and_sign: 4,
                     after_sign_in: 5,
                     before_sign_out: 3,
                     build_claims: 3,
                     default_token_type: 0,
                     on_exchange: 3,
                     on_revoke: 3,
                     on_refresh: 3,
                     on_verify: 3,
                     peek: 1,
                     verify_claims: 2,
                     sliding_cookie: 3
    end
  end

  @doc """
  Provides the current system time in seconds.
  """
  @spec timestamp() :: pos_integer
  def timestamp, do: System.system_time(:second)

  @doc """
  Converts keys in a map or list of maps to strings.
  """

  @spec stringify_keys(map | list | any) :: map | list | any
  def stringify_keys(map) when is_map(map) do
    for {k, v} <- map, into: %{}, do: {to_string(k), stringify_keys(v)}
  end

  def stringify_keys(list) when is_list(list) do
    for item <- list, into: [], do: stringify_keys(item)
  end

  def stringify_keys(value), do: value

  @doc """
  Returns an inspection of the token (at least claims)
  without any verification.

  This should not be relied on since there is no verification.

  The implementation is provided by the implementation module specified.
  See the documentation for your implementation / token module for full details.
  """

  @spec peek(module, Guardian.Token.token()) :: %{claims: map}
  def peek(mod, token) do
    mod.peek(token)
  end

  @doc """
  Creates a signed token for a resource.

  The actual encoding depends on the implementation module
  which should be referenced for specifics.

  ### Lifecycle
  Once called, a number of callbacks will be invoked on the implementation module:

  * `subject_for_token` - gets the subject from the resource
  * `build_claims` - allows the implementation module to add or modify claims
    before the token is created
  * `after_encode_and_sign`

  ### Options
  The options will be passed through to the implementation / token modules
  and the appropriate callbacks.

  * `ttl` - How long to keep the token alive for. If not included the default will be used.
  * `token_type` - The type of token to generate if different from the default.

  The `ttl` option should take `{integer, unit}` where unit is one of:

  * `:second` | `:seconds`
  * `:minute` | `:minutes`
  * `:hour` | `:hours`
  * `:week` | `:weeks`

  See the documentation for your implementation / token module for more information on
  which options are available for your implementation / token module.
  """

  @spec encode_and_sign(module, any, Guardian.Token.claims(), options) ::
          {:ok, Guardian.Token.token(), Guardian.Token.claims()} | {:error, any}
  def encode_and_sign(mod, resource, claims \\ %{}, opts \\ []) do
    claims =
      claims
      |> Enum.into(%{})
      |> Guardian.stringify_keys()

    token_mod = Guardian.token_module(mod)

    with {:ok, subject} <- returning_tuple({mod, :subject_for_token, [resource, claims]}),
         {:ok, claims} <- returning_tuple({token_mod, :build_claims, [mod, resource, subject, claims, opts]}),
         {:ok, claims} <- returning_tuple({mod, :build_claims, [claims, resource, opts]}),
         {:ok, token} <- returning_tuple({token_mod, :create_token, [mod, claims, opts]}),
         {:ok, _} <- returning_tuple({mod, :after_encode_and_sign, [resource, claims, token, opts]}) do
      {:ok, token, claims}
    end
  end

  @doc """
  Decodes a token using the configuration of the implementation module.

  This will, using that configuration, delegate to the token module.

  Once the token module has decoded the token, your implementation module
  has an opportunity to further verify the claims contained in the token
  using the `verify_claims` callback.

  ### Lifecycle
  Once called, a number of callbacks will be invoked on the implementation module:

  * `verify_claims` - add custom claim verification, returns an error if the claims are not valid
  * `on_verify` - called after a successful verification

  ### Options
  The options will be passed through to the implementation / token modules
  and the appropriate callbacks.

  See the documentation for your implementation / token modules for more information on
  which options are available.
  """

  @spec decode_and_verify(module, Guardian.Token.token(), Guardian.Token.claims(), options) ::
          {:ok, Guardian.Token.claims()} | {:error, any}
  def decode_and_verify(mod, token, claims_to_check \\ %{}, opts \\ []) do
    claims_to_check = claims_to_check |> Enum.into(%{}) |> Guardian.stringify_keys()
    token_mod = Guardian.token_module(mod)

    with {:ok, claims} <- returning_tuple({token_mod, :decode_token, [mod, token, opts]}),
         {:ok, claims} <- Verify.verify_literal_claims(claims, claims_to_check, opts),
         {:ok, claims} <- returning_tuple({token_mod, :verify_claims, [mod, claims, opts]}),
         {:ok, claims} <- returning_tuple({mod, :verify_claims, [claims, opts]}),
         {:ok, claims} <- returning_tuple({mod, :on_verify, [claims, token, opts]}) do
      {:ok, claims}
    end
  rescue
    e -> {:error, e}
  end

  @doc """
  Fetch the resource and claims directly from a token.

  This is a convenience function that first decodes the token using
  `Guardian.decode_and_verify/4` and then loads the resource.
  """

  @spec resource_from_token(
          mod :: module,
          token :: Guardian.Token.token(),
          claims_to_check :: Guardian.Token.claims() | nil,
          opts :: options
        ) :: {:ok, Guardian.Token.resource(), Guardian.Token.claims()} | {:error, any}
  def resource_from_token(mod, token, claims_to_check \\ %{}, opts \\ []) do
    with {:ok, claims} <- Guardian.decode_and_verify(mod, token, claims_to_check, opts),
         {:ok, resource} <- returning_tuple({mod, :resource_from_claims, [claims]}) do
      {:ok, resource, claims}
    end
  end

  @doc """
  Revoke a token.

  Note: This is entirely dependent on the token module and callbacks.

  ### Lifecycle

  * `<TokenModule>.revoke`
  * `<ImplModule>.on_revoke`

  ### Options

  The options are passed through to the token module and callback
  so check the documentation for your token module.
  """
  @spec revoke(module, Guardian.Token.token(), options) :: {:ok, Guardian.Token.claims()} | {:error, any}
  def revoke(mod, token, opts \\ []) do
    token_mod = Guardian.token_module(mod)

    with %{claims: claims} <- mod.peek(token),
         {:ok, claims} <- returning_tuple({token_mod, :revoke, [mod, claims, token, opts]}),
         {:ok, claims} <- returning_tuple({mod, :on_revoke, [claims, token, opts]}) do
      {:ok, claims}
    else
      nil -> {:error, :not_found}
      {:error, _} = err -> err
    end
  end

  @doc """
  Refreshes a token keeping all main claims intact.

  ### Options

  * `ttl` - How long to keep the token alive for. If not included the default will be used.

  The `ttl` option should take `{integer, unit}` where unit is one of:

  * `:second` | `:seconds`
  * `:minute` | `:minutes`
  * `:hour` | `:hours`
  * `:day` | `:days`
  * `:week` | `:weeks`

  See documentation for your token module for other options.
  """

  @spec refresh(module, Guardian.Token.token(), options) ::
          {
            :ok,
            {Guardian.Token.token(), Guardian.Token.claims()},
            {Guardian.Token.token(), Guardian.Token.claims()}
          }
          | {:error, any}
  def refresh(mod, old_token, opts) do
    with token_mod <- Guardian.token_module(mod),
         {:ok, _claims} <- apply(mod, :decode_and_verify, [old_token, %{}, opts]),
         {:ok, old_stuff, new_stuff} <- apply(token_mod, :refresh, [mod, old_token, opts]) do
      apply(mod, :on_refresh, [old_stuff, new_stuff, opts])
    else
      {:error, _} = err -> err
      err -> {:error, err}
    end
  end

  @doc """
  Exchanges one token for another with different token types.

  The token is first decoded and verified to ensure that there is no escalation
  Of privileges.

  Tokens must have their type included in the `from_type` argument.

  ### Lifecycle

  * `<TokenModule>.exchange` - exchange the old token for the new one
  * `<ImplModule>.on_exchange` - will be invoked after the exchange happens

  ### Options

  All options are passed through all calls to the token module and
  appropriate callbacks.
  """
  @spec exchange(
          module,
          Guardian.Token.token(),
          String.t() | [String.t(), ...],
          String.t(),
          options
        ) ::
          {
            :ok,
            {Guardian.Token.token(), Guardian.Token.claims()},
            {Guardian.Token.token(), Guardian.Token.claims()}
          }
          | {:error, any}
  def exchange(mod, old_token, from_type, to_type, opts) do
    with token_mod <- Guardian.token_module(mod),
         {:ok, claims} <- apply(mod, :decode_and_verify, [old_token, %{}, opts]),
         :ok <- validate_exchange_type(claims, from_type),
         {:ok, old_stuff, new_stuff} <- apply(token_mod, :exchange, [mod, old_token, from_type, to_type, opts]) do
      apply(mod, :on_exchange, [old_stuff, new_stuff, opts])
    else
      {:error, _} = err -> err
      err -> {:error, err}
    end
  end

  @doc false
  def returning_tuple({mod, func, args}) do
    result = apply(mod, func, args)

    case result do
      {:ok, _} ->
        result

      {:error, _} ->
        result

      resp ->
        raise MalformedReturnValueError,
          message: "Expected `{:ok, result}` or `{:error, reason}` from #{mod}##{func}, got: #{inspect(resp)}"
    end
  end

  @doc false
  def token_module(mod) do
    apply(mod, :config, [:token_module, @default_token_module])
  end

  @doc false
  def ttl_to_seconds({seconds, unit}) when unit in [:second, :seconds],
    do: seconds

  def ttl_to_seconds({minutes, unit}) when unit in [:minute, :minutes],
    do: minutes * 60

  def ttl_to_seconds({hours, unit}) when unit in [:hour, :hours],
    do: hours * 60 * 60

  def ttl_to_seconds({days, unit}) when unit in [:day, :days],
    do: days * 24 * 60 * 60

  def ttl_to_seconds({weeks, unit}) when unit in [:week, :weeks],
    do: weeks * 7 * 24 * 60 * 60

  def ttl_to_seconds({_, units}),
    do: raise("Unknown Units: #{units}")

  defp validate_exchange_type(claims, from_type) when is_binary(from_type),
    do: validate_exchange_type(claims, [from_type])

  defp validate_exchange_type(claims, from_type) do
    if Enum.member?(from_type, claims["typ"]), do: :ok, else: {:error, :invalid_token_type}
  end
end
