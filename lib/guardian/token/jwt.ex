defmodule Guardian.Token.Jwt do
  @moduledoc """
  Deals with things JWT

  ## Configuration

  * issuer
  * secret_key
  * allowed_algos
  """
  @behavior Guardian.Token

  alias Guardian.Config

  @default_algos ["HS512"]

  @doc """
  Read the header of the token.
  This is not a verified read, it does not check the signature.
  """
  def peek_header(token) do
    JOSE.JWT.peek_protected(token).fields
  end

  @doc """
  Read the claims of the token.
  This is not a verified read, it does not check the signature.
  """
  def peek_claims(token) do
    JOSE.JWT.peek_payload(token).fields
  end

  def sign_claims(mod, claims, options \\ []) do
    headers = fetch_headers(mod, options)
    secret = fetch_secret(mod, options)
    algos = fetch_allowed_algos(mod, options)

    {_, token} =
      secret
      |> jose_jwk()
      |> JOSE.JWT.sign(jose_jws(headers), claims)
      |> JOSE.JWS.compact

    {:ok, token}
  end

  def build_claims(mod, sub, token_type, claims \\ %{}, options \\ []) do
    claims
    |> app_claims(options)
    |> set_permissions(options)
    |> set_type(token_type, options)
    |> set_sub(sub, options)
    |> set_ttl(options)
    |> set_aud(options)
  end

  def decode_token(mod, token, options \\ []) do
    secret =
      mod
      |> fetch_secret(options)
      |> jose_jwk()

    case JOSE.JWT.verify_strict(secret, fetch_allowed_algos(), token) do
      {true, jose_jwt, _} ->  {:ok, jose_jwt.fields}
      {false, _, _} -> {:error, :invalid_token}
    end
  end

  defp jose_jws(mod, opts \\ []) do
    algos = fetch_allowed_algos(mod, opts) || @default_algos
    headers = Keyword.get(opts, :headers, [])
    Map.merge(%{"alg" => hd(algos)}, headers)
  end

  defp jose_jwk(the_secret = %JOSE.JWK{}), do: the_secret
  defp jose_jwk(the_secret) when is_binary(the_secret), do: JOSE.JWK.from_oct(the_secret)
  defp jose_jwk(the_secret) when is_map(the_secret), do: JOSE.JWK.from_map(the_secret)
  defp jose_jwk(value), do: Config.resolve_value(value)

  defp fetch_headers(mod, opts) do
    headers = Keyword.get(opts, :headers)
  end

  defp fetch_allowed_algos(mod, opts) do
    allowed = Keyword.get(opts, :allowed_algos)
    if allowed do
      allowed
    else
      mod
      |> apply(:config, [])
      |> Map.get(:allowed_algos, @default_algos)
    end
  end

  defp fetch_secret(mod, opts) do
    secret = Keyword.get(opts, :secret)
    if secret do
      secret
    else
      mod
      |> apply(:config, [])
      |> Map.get(:secret_key)
    end
  end
end
