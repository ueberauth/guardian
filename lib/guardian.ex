defmodule Guardian do
  @moduledoc """
  TODO: Fill me in
  """

  @type options :: Keyword.t

  @default_token_module Guardian.Token.Jwt

  @doc """
  Encodes the subject into a token in the "sub" field
  """
  @callback subject_for_token(
    resource :: Guardian.Token.resource(),
    claims :: Guardian.Token.claims()
  ) :: {:ok, String.t} | {:error, atom()}

  @callback resource_from_claims(
    claims :: Guardian.Token.claims()
  ) :: {:ok, Guardian.Token.resource()} | {:error, atom()}

  @callback build_claims(
    claims :: Guardian.Token.claims(),
    resource :: Guardian.Token.resource(),
    opts :: options()
  ) :: {:ok, Guardian.Token.claims()} | {:error, atom()}

  @callback after_encode_and_sign(
    resource :: any,
    claims :: Guardian.Token.claims(),
    token :: Guardian.Token.token(),
    options :: options()
  ) :: {:ok, Guardian.Token.token()} | {:error, atom()}

  @callback after_sign_in(
    conn :: Plug.Conn.t,
    resource :: any(),
    token :: Guardian.Token.token(),
    claims :: Guardian.Token.claims(),
    options :: Guardian.options()
  ) :: {:ok, Plug.Conn.t} | {:error, atom()}

  @callback before_sign_out(
    conn :: Plug.Conn.t,
    location :: atom() | nil,
    options :: Guardian.options()
  ) :: {:ok, Plug.Conn.t()} | {:error, atom()}

  @callback verify_claims(
    claims :: Guardian.Token.claims(),
    options :: options()
  ) :: {:ok, Guardian.Token.claims()} | {:error, atom()}

  @callback on_verify(
    claims :: Guardian.Token.claims(),
    token :: Guardian.Token.token(),
    options :: options()
  ) :: {:ok, Guardian.Token.claims()} | {:error, any()}

  @callback on_revoke(
    claims :: Guardian.Token.claims(),
    token :: Guardian.Token.token(),
    options :: options()
  ) :: {:ok, Guardian.Token.claims()} | {:error, any()}

  @callback on_refresh(
    old_token_and_claims :: {Guardian.Token.token(), Guardian.Token.claims()},
    new_token_and_claims :: {Guardian.Token.token(), Guardian.Token.claims()},
    options :: options()
  ) :: {
    :ok,
    {Guardian.Token.token(), Guardian.Token.claims()},
    {Guardian.Token.token(), Guardian.Token.claims()}
  } | {:error, any()}

  @callback on_exchange(
    old_token_and_claims :: {Guardian.Token.token(), Guardian.Token.claims()},
    new_token_and_claims :: {Guardian.Token.token(), Guardian.Token.claims()},
    options :: options()
  ) :: {
    :ok,
    {Guardian.Token.token(), Guardian.Token.claims()},
    {Guardian.Token.token(), Guardian.Token.claims()}
  } | {:error, any()}

  defmacro __using__(opts \\ []) do
    otp_app = Keyword.get(opts, :otp_app)

    quote do
      @behaviour Guardian

      # credo:disable-for-next-line /AliasUsage/
      Guardian.Config.merge_config_options(__MODULE__, unquote(opts))

      __MODULE__
      |> Module.concat(:Plug)
      |> Module.create(
        quote do use Guardian.Plug, unquote(__MODULE__) end,
        Macro.Env.location(__ENV__)
      )

      def default_token_type, do: "access"

      def config do
        Application.get_env(unquote(otp_app), __MODULE__)
      end

      def config(key, default \\ nil) do
        alias Guardian.{Config}
        config()
        |> Keyword.get(key, default)
        |> Config.resolve_value()
      end

      def peek(token), do: Guardian.peek(__MODULE__, token)

      def encode_and_sign(resource, claims \\ %{}, opts \\ []) do
        Guardian.encode_and_sign(__MODULE__, resource, claims, opts)
      end

      def decode_and_verify(token, claims_to_check \\ %{}, opts \\ []) do
        Guardian.decode_and_verify(__MODULE__, token, claims_to_check, opts)
      end

      def revoke(token, opts \\ []) do
        Guardian.revoke(__MODULE__, token, opts)
      end

      def refresh(old_token, opts \\ []) do
        Guardian.refresh(__MODULE__, old_token, opts)
      end

      def exchange(token, from_type, to_type, options \\ []) do
        Guardian.exchange(__MODULE__, token, from_type, to_type, options)
      end

      def after_encode_and_sign(_r, _claims, token, _), do: {:ok, token}
      def after_sign_in(conn, _r, _t, _c, _o), do: {:ok, conn}
      def before_sign_out(conn, _location, _opts), do: {:ok, conn}
      def on_verify(claims, _token, _options), do: {:ok, claims}
      def on_revoke(claims, _token, _options), do: {:ok, claims}
      def on_refresh(old_stuff, new_stuff, _options) do
        {:ok, old_stuff, new_stuff}
      end
      def on_exchange(old_stuff, new_stuff, _options) do
        {:ok, old_stuff, new_stuff}
      end

      def build_claims(c, _, _), do: {:ok, c}
      def verify_claims(claims, _options), do: {:ok, claims}

      defoverridable [
        after_encode_and_sign: 4,
        after_sign_in: 5,
        before_sign_out: 3,
        build_claims: 3,
        default_token_type: 0,
        on_exchange: 3,
        on_revoke: 3,
        on_refresh: 3,
        on_verify: 3,
        verify_claims: 2,
      ]
    end
  end

  def timestamp do
    System.system_time(:seconds)
  end

  def stringify_keys(map) when is_map(map) do
    for {k, v} <- map, into: %{}, do: {to_string(k), stringify_keys(v)}
  end
  def stringify_keys(list) when is_list(list) do
    for item <- list, into: [], do: stringify_keys(item)
  end
  def stringify_keys(value), do: value

  def peek(mod, token) do
    token_mod = apply(mod, :config, [:token_module, @default_token_module])
    apply(token_mod, :peek, [token])
  end

  def encode_and_sign(mod, resource, claims \\ %{}, opts \\ []) do
    claims =
      claims
      |> Enum.into(%{})
      |> Guardian.stringify_keys()

    token_mod = apply(mod, :config, [:token_module, @default_token_module])

    with {:ok, subject} <- apply(mod, :subject_for_token, [resource, claims]),
         {:ok, claims} <- apply(
           token_mod,
           :build_claims,
           [mod, resource, subject, claims, opts]
         ),
         {:ok, claims} <- apply(mod, :build_claims, [claims, resource, opts]),
         {:ok, token} <- apply(token_mod, :create_token, [mod, claims, opts]),
         {:ok, _} <- apply(
           mod,
           :after_encode_and_sign,
           [resource, claims, token, opts]
         )
    do
      {:ok, token, claims}
    else
      {:error, _} = err -> err
      err -> {:error, err}
    end
  end

  def decode_and_verify(mod, token, claims_to_check \\ %{}, opts \\ []) do
    alias Guardian.Token.{Verify}

    claims_to_check =
      claims_to_check
      |> Enum.into(%{})
      |> Guardian.stringify_keys()

    token_mod = apply(mod, :config, [:token_module, @default_token_module])

    try do
      with {:ok, claims} <- apply(token_mod, :decode_token, [mod, token, opts]),
           {:ok, claims} <- Verify
                            .verify_literal_claims(
                              claims,
                              claims_to_check,
                              opts
                            ),
           {:ok, claims} <- apply(
             token_mod,
             :verify_claims,
             [mod, claims, opts]
           ),
           {:ok, claims} <- apply(
             mod,
             :verify_claims,
             [claims, opts]
           ),
           {:ok, claims} <- apply(mod, :on_verify, [claims, token, opts])
      do
        {:ok, claims}
      else
        {:error, _} = err -> err
        err -> {:error, err}
      end
    rescue
      e -> {:error, e}
    end
  end

  def revoke(mod, token, options \\ []) do
    token_mod = apply(mod, :config, [:token_module, @default_token_module])
    %{claims: claims} = Guardian.peek(mod, token)

    with {:ok, claims} <- apply(
                            token_mod,
                            :revoke,
                            [mod, claims, token, options]
                          ),
         {:ok, claims} <- apply(mod, :on_revoke, [claims, token, options])
    do
      {:ok, claims}
    else
      {:error, _} = err -> err
      err -> {:error, err}
    end
  end

  def refresh(mod, old_token, opts) do
    with token_mod <- apply(
           mod,
           :config,
           [:token_module, @default_token_module]
         ),
         {:ok, old_stuff, new_stuff} <- apply(
           token_mod,
           :refresh,
           [mod, old_token, opts]
         )
    do
      apply(mod, :on_refresh, [old_stuff, new_stuff, opts])
    else
      {:error, _} = err -> err
      err -> {:error, err}
    end
  end

  def exchange(mod, old_token, from_type, to_type, options) do
    with token_mod <- apply(
           mod,
           :config,
           [:token_module, @default_token_module]
         ),
         {:ok, old_stuff, new_stuff} <- apply(
           token_mod,
           :exchange,
           [mod, old_token, from_type, to_type, options]
         )
    do
      apply(mod, :on_exchange, [old_stuff, new_stuff, options])
    else
      {:error, _} = err -> err
      err -> {:error, err}
    end
  end
end
