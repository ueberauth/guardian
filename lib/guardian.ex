defmodule Guardian do
  @type token_type :: String.t
  @type options :: Keyword.t

  @default_token_module Guardian.Token.Jwt
  @default_token_type "access"

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
    location :: atom() | nil
  ) :: Plug.Conn.t

  @callback before_sign_out(
    conn :: Plug.Conn.t,
    location :: atom() | nil
  ) :: Plug.Conn.t

  @callback verify_claims(
    claims :: Guardian.Token.claims(),
    claims_to_check :: Guardian.Token.claims(),
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

  defmacro __using__(opts \\ []) do
    otp_app = Keyword.get(opts, :otp_app)

    quote do
      @behaviour Guardian
      Guardian.Config.merge_config_options(__MODULE__, unquote(opts))

      def default_token_type, do: "access"

      def config do
        Application.get_env(unquote(otp_app), __MODULE__)
      end

      def config(key, default \\ nil) do
        config()
        |> Keyword.get(key, default)
        |> Guardian.Config.resolve_value()
      end

      def encode_and_sign(resource, token_type \\ nil, claims \\ %{}, opts \\ []) do
        token_type = token_type || default_token_type()
        Guardian.encode_and_sign(__MODULE__, resource, token_type, claims, opts)
      end

      def decode_and_verify(token, claims_to_check \\ %{}, opts \\ []) do
        Guardian.decode_and_verify(__MODULE__, token, claims_to_check, opts)
      end

      def after_encode_and_sign(_r, _claims, token, _), do: {:ok, token}
      def after_sign_in(conn, _location), do: conn
      def before_sign_out(conn, _location), do: conn
      def on_verify(claims, _token, _options), do: {:ok, claims}
      def on_revoke(claims, _token, _options), do: {:ok, claims}

      def build_claims(c, _, _), do: {:ok, c}
      def verify_claims(claims, _claims_to_check, _options), do: {:ok, claims}

      @defoverridable [
        after_encode_and_sign: 5,
        after_sign_in: 2,
        before_sign_out: 2,
        build_claims: 1,
        default_token_type: 0,
        on_revoke: 3,
        on_verify: 3,
        verify_claims: 3,
      ]
    end
  end

  def timestamp do
    System.system_time(:seconds)
  end

  def stringify_keys(map) do
    for {k,v} <- map, into: %{}, do: {to_string(k), v}
  end

  def encode_and_sign(mod, resource, token_type, claims \\ %{}, opts \\ []) do
    claims =
      claims
      |> Enum.into(%{})
      |> Guardian.stringify_keys()

    token_mod = apply(mod, :config, [:token_module, @default_token_module])

    with {:ok, subject} <- apply(mod, :subject_for_token, [resource, claims]),
         claims <- apply(
           token_mod,
           :build_claims,
           [mod, resource, subject, token_type, claims, opts]
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
    end
  end

  def decode_and_verify(mod, token, claims_to_check \\ %{}, opts \\ []) do
    claims_to_check =
      claims_to_check
      |> Enum.into(%{})
      |> Guardian.stringify_keys()

    token_mod = apply(mod, :config, [:token_module, @default_token_module])

    try do
      with {:ok, claims} <- apply(token_mod, :decode_token, [mod, token, opts]),
           {:ok, claims} <- apply(
             token_mod,
             :verify_claims,
             [mod, claims, claims_to_check, opts]
           ),
           {:ok, claims} <- apply(
             mod,
             :verify_claims,
             [claims, claims_to_check, opts]
           ),
           {:ok, claims} <- apply(mod, :on_verify, [claims, token, opts])
      do
        {:ok, claims}
      end
    rescue
      e -> {:error, e}
    end
  end
end
