defmodule GuardianTest do
  use ExUnit.Case, async: true

  setup do
    claims = %{
      "aud" => "User:1",
      "typ" => "token",
      "exp" => Guardian.Utils.timestamp + 100_00,
      "iat" => Guardian.Utils.timestamp,
      "iss" => "MyApp",
      "sub" => "User:1",
      "something_else" => "foo"}

    config = Application.get_env(:guardian, Guardian)
    algo = hd(Keyword.get(config, :allowed_algos))
    secret = Keyword.get(config, :secret_key)

    jose_jws = %{"alg" => algo}
    jose_jwk = %{"kty" => "oct", "k" => :base64url.encode(secret)}

    { _, jwt } = jose_jwk
                  |> JOSE.JWT.sign(jose_jws, claims)
                  |> JOSE.JWS.compact

    { :ok, %{
        claims: claims,
        jwt: jwt,
        jose_jws: jose_jws,
        jose_jwk: jose_jwk
      }
    }
  end

  test "config with a value" do
    assert Guardian.config(:issuer) == "MyApp"
  end

  test "config with no value" do
    assert Guardian.config(:not_a_thing) == nil
  end

  test "config with a default value" do
    assert Guardian.config(:not_a_thing, :this_is_a_thing) == :this_is_a_thing
  end

  test "it fetches the currently configured serializer" do
    assert Guardian.serializer == Guardian.TestGuardianSerializer
  end

  test "it returns the current app name" do
    assert Guardian.issuer == "MyApp"
  end

  test "it verifies the jwt", context do
    assert Guardian.decode_and_verify(context.jwt) == { :ok, context.claims }
  end

  test "verifies the issuer", context do
    assert Guardian.decode_and_verify(context.jwt) == { :ok, context.claims }
  end

  test "fails if the issuer is not correct", context do
    claims = %{
      typ: "token",
      exp: Guardian.Utils.timestamp + 100_00,
      iat: Guardian.Utils.timestamp,
      iss: "not the issuer",
      sub: "User:1"
    }

    { _, jwt } = context.jose_jwk
                  |> JOSE.JWT.sign(context.jose_jws, claims)
                  |> JOSE.JWS.compact

    assert Guardian.decode_and_verify(jwt) == {:error, :invalid_issuer}
  end

  test "fails if the expiry has passed", context do
    claims = Map.put(context.claims, "exp", Guardian.Utils.timestamp - 10)
    { _, jwt } = context.jose_jwk
                  |> JOSE.JWT.sign(context.jose_jws, claims)
                  |> JOSE.JWS.compact

    assert Guardian.decode_and_verify(jwt) == { :error, :token_expired }
  end

  test "it is invalid if the typ is incorrect", context do
    response = Guardian.decode_and_verify(
      context.jwt,
      %{typ: "something_else"}
    )

    assert response == { :error, :invalid_type }
  end

  test "verify! with a jwt", context do
    assert Guardian.decode_and_verify!(context.jwt) == context.claims
  end

  test "verify! with a bad token", context do
    claims = Map.put(context.claims, "exp", Guardian.Utils.timestamp - 10)
    { _, jwt } = context.jose_jwk
                  |> JOSE.JWT.sign(context.jose_jws, claims)
                  |> JOSE.JWS.compact

    assert_raise(RuntimeError, fn() -> Guardian.decode_and_verify!(jwt) end)
  end

  test "serializer" do
    assert Guardian.serializer == Guardian.TestGuardianSerializer
  end

  test "encode_and_sign(object)" do
    { :ok, jwt, _ } = Guardian.encode_and_sign("thinger")

    { :ok, claims } = Guardian.decode_and_verify(jwt)
    assert claims["typ"] == "token"
    assert claims["aud"] == "thinger"
    assert claims["sub"] == "thinger"
    assert claims["iat"]
    assert claims["exp"] > claims["iat"]
    assert claims["iss"] == Guardian.issuer
  end

  test "encode_and_sign(object, audience)" do
    { :ok, jwt, _ } = Guardian.encode_and_sign("thinger", "my_type")

    { :ok, claims } = Guardian.decode_and_verify(jwt)
    assert claims["typ"] == "my_type"
    assert claims["aud"] == "thinger"
    assert claims["sub"] == "thinger"
    assert claims["iat"]
    assert claims["exp"] > claims["iat"]
    assert claims["iss"] == Guardian.issuer
  end

  test "encode_and_sign(object, type, claims)" do
    { :ok, jwt, _ } = Guardian.encode_and_sign(
      "thinger",
      "my_type",
      some: "thing"
    )

    { :ok, claims } = Guardian.decode_and_verify(jwt)
    assert claims["typ"] == "my_type"
    assert claims["aud"] == "thinger"
    assert claims["sub"] == "thinger"
    assert claims["iat"]
    assert claims["exp"] > claims["iat"]
    assert claims["iss"] == Guardian.issuer
    assert claims["some"] == "thing"
  end

  test "encode_and_sign with a serializer error" do
    {:error, reason} = Guardian.encode_and_sign(%{error: :unknown})
    assert reason
  end

  test "encode_and_sign with custom secret" do
    secret = "ABCDEF"
    { :ok, jwt, _ } = Guardian.encode_and_sign(
      "thinger",
      "my_type",
      some: "thing",
      secret: secret
    )

    {:error, :invalid_token} = Guardian.decode_and_verify(jwt)
    {:ok, _claims} = Guardian.decode_and_verify(jwt, %{secret: secret})
  end

  test "peeking at the headers" do
    secret = "ABCDEF"
    { :ok, jwt, _ } = Guardian.encode_and_sign(
      "thinger",
      "my_type",
      some: "thing",
      secret: secret,
      headers: %{"foo" => "bar"}
    )

    header = Guardian.peek_header(jwt)
    assert header["foo"] == "bar"
  end

  test "peeking at the payload" do
    secret = "ABCDEF"
    { :ok, jwt, _ } = Guardian.encode_and_sign(
      "thinger",
      "my_type",
      some: "thing",
      secret: secret,
      headers: %{"foo" => "bar"}
    )

    header = Guardian.peek_claims(jwt)
    assert header["some"] == "thing"
  end

  test "revoke" do
    {:ok, jwt, claims} = Guardian.encode_and_sign(
      "thinger",
      "my_type",
      some: "thing"
    )

    assert Guardian.revoke!(jwt, claims) == :ok
  end

  test "refresh" do

    old_claims = Guardian.Claims.app_claims
                 |> Map.put("iat", Guardian.Utils.timestamp - 100)
                 |> Map.put("exp", Guardian.Utils.timestamp + 100)

    {:ok, jwt, claims} = Guardian.encode_and_sign(
      "thinger",
      "my_type",
      old_claims
    )

    {:ok, new_jwt, new_claims} = Guardian.refresh!(jwt, claims)

    refute jwt == new_jwt

    refute Map.get(new_claims, "jti") == nil
    refute Map.get(new_claims, "jti") == Map.get(claims, "jti")

    refute Map.get(new_claims, "iat") == nil
    refute Map.get(new_claims, "iat") == Map.get(claims, "iat")

    refute Map.get(new_claims, "exp") == nil
    refute Map.get(new_claims, "exp") == Map.get(claims, "exp")
  end
end
