defmodule Guardian do
  @type token_type :: String.t

  @doc """
  Encodes the subject into a token in the "sub" field
  """
  @callback subject_for_token(
    resource :: any,
    claims :: map
  ) :: string

  @callback resource_from_claims(
    claims :: map
  ) :: any

  @callback token_module() :: Module.t
  @callback config() :: map

  @callback encode_and_sign(
    resource :: any,
    type :: token_type,
    claims :: map,
    options :: Keyword.t
  ) :: {:ok, Token.jwt, map} |
       Token.signing_error |
       Token.encoding_error

  @callback decode_and_verify(
    token :: Token.jwt,
    claims_to_check :: map,
    options :: Keyword.t
  ) :: {:ok, map} |
       {:error, atom}

  defmacro __using__(opts) do
    opts = Enum.into(opts, %{})
    otp_app = Map.get(opts, :otp_app)
    token_mod = Map.get(opts, :token_module)

    quote do
      @behaviour Guardian

      def config do
        Application.get_env(unquote(otp_app), __MODULE__)
      end

      def token_module do
        unquote(token_mod) ||
          Map.get(config, :token_module, Guardian.Token.Jwt)
      end

      def encode_and_sign(resource, token_type, claims \\ [], opts \\ [])
        Guardian.encode_and_sign(__MODULE__, resource, token_type, claims, opts)
      end

      def decode_and_verify(token, claims_to_check \\ %{}, opts \\ [])
        Guardian.decode_and_verify(__MODULE__, token, claims_to_check, opts)
      end

      @defoverridable [config: 0, token_module: 0, secret: 2]
    end
  end

  def encode_and_sign(mod, resource, token_type, claims \\ %{}, opts \\ []) do
    claims = Enum.into(claims, %{})
    token_mod = apply(mod, :token_module, [])
    sub = apply(mod, :subject_for_token, [resource, claims])

    case sub do
      {:ok, subject} ->
        claims = stringify_keys(claims)
        full_claims = apply(
          token_mod,
          :build_claims,
          [mod, subject, token_type, claims, opts]
        )

        case full_claims do
          {:ok, claims} ->
            apply(token_mod, :sign_claims, [mod, claims, opts])
          {:error, reason} -> {:error, reason}
        end
      {:error, reason} -> {:error, reason}
    end
  end

  def decode_and_verify(mod, token, claims_to_check \\ %{}, opts \\ []) do
    claims_to_check = Enum.into(claims_to_check, %{})
    token_mod = apply(mod, :token_module, [])
    decode_result = apply(token_mod, :decode_token, [mod, token, opts])

    case decode_result do
      {:ok, jwt}
    end

  end
end
