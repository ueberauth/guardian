defmodule Guardian.Encoder.JWT do
  @moduledoc false
  @behaviour Guardian.ClaimValidation

  @default_algos ["HS512"]

  use Guardian.ClaimValidation

  def validate_claim(_, _, _), do: :ok

  defp jose_jws(headers) do
    Map.merge(%{"alg" => hd(allowed_algos())}, headers)
  end

  defp jose_jwk(the_secret = %JOSE.JWK{}), do: the_secret
  defp jose_jwk(the_secret) when is_binary(the_secret), do: JOSE.JWK.from_oct(the_secret)
  defp jose_jwk(the_secret) when is_map(the_secret), do: JOSE.JWK.from_map(the_secret)
  defp jose_jwk({mod, fun}),       do: jose_jwk(:erlang.apply(mod, fun, []))
  defp jose_jwk({mod, fun, args}), do: jose_jwk(:erlang.apply(mod, fun, args))
  defp jose_jwk(nil), do: jose_jwk(Guardian.config(:secret_key) || false)

  def encode_claims(claims) do
    {headers, claims} = strip_value(claims, "headers", %{})
    {secret, claims} = strip_value(claims, "secret")
    {_, token} = secret
                   |> jose_jwk()
                   |> JOSE.JWT.sign(jose_jws(headers), claims)
                   |> JOSE.JWS.compact
    {:ok, token}
  end

  def decode_token(token, secret) do
    secret = secret || Guardian.config(:secret_key)
    case JOSE.JWT.verify_strict(jose_jwk(secret), allowed_algos(), token) do
      {true, jose_jwt, _} ->  {:ok, jose_jwt.fields}
      {false, _, _} -> {:error, :invalid_token}
    end
  end

  defp allowed_algos, do: Guardian.config(:allowed_algos, @default_algos)

  defp strip_value(map, key, default \\ nil) do
    value = Map.get(map, key, default)
    {value, Map.drop(map, [key])}
  end

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
end
