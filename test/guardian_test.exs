defmodule GuardianTest do
  use ExUnit.Case, async: true

  setup do
    claims = %{
      "aud" => "token",
      "exp" => Guardian.Utils.timestamp + 100_00,
      "iat" => Guardian.Utils.timestamp,
      "iss" => "MyApp",
      "sub" => "User:1",
      "something_else" => "foo"}

    config = Application.get_env(:guardian, Guardian)
    algo = hd(Dict.get(config, :allowed_algos))
    secret = Dict.get(config, :secret_key)

    jose_jws = %{"alg" => algo}
    jose_jwk = %{"kty" => "oct", "k" => :base64url.encode(secret)}

    { _, jwt } = JOSE.JWT.sign(jose_jwk, jose_jws, claims) |> JOSE.JWS.compact

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
    claims = %{aud: "token", exp: Guardian.Utils.timestamp + 100_00, iat: Guardian.Utils.timestamp, iss: "not the issuer", sub: "User:1"}
    { _, jwt } = JOSE.JWT.sign(context.jose_jwk, context.jose_jws, claims) |> JOSE.JWS.compact

    assert Guardian.decode_and_verify(jwt) == { :error, :invalid_issuer }
  end

  test "fails if the expiry has passed", context do
    claims = Dict.put(context.claims, "exp", Guardian.Utils.timestamp - 10)
    { _, jwt } = JOSE.JWT.sign(context.jose_jwk, context.jose_jws, claims) |> JOSE.JWS.compact

    assert Guardian.decode_and_verify(jwt) == { :error, :token_expired }
  end

  test "it is invalid if the aud is incorrect", context do
    assert Guardian.decode_and_verify(context.jwt, %{ aud: "something_else"}) == { :error, :invalid_audience }
  end

  test "verify! with a jwt", context do
    assert Guardian.decode_and_verify!(context.jwt) == context.claims
  end

  test "verify! with a bad token", context do
    claims = Dict.put(context.claims, "exp", Guardian.Utils.timestamp - 10)
    { _, jwt } = JOSE.JWT.sign(context.jose_jwk, context.jose_jws, claims) |> JOSE.JWS.compact

    assert_raise(RuntimeError, fn() -> Guardian.decode_and_verify!(jwt) end)
  end

  test "serializer" do
    assert Guardian.serializer == Guardian.TestGuardianSerializer
  end

  test "encode_and_sign(object)" do
    { :ok, jwt, _ } = Guardian.encode_and_sign("thinger")

    { :ok, claims } = Guardian.decode_and_verify(jwt)
    assert claims["aud"] == "token"
    assert claims["sub"] == "thinger"
    assert claims["iat"]
    assert claims["exp"] > claims["iat"]
    assert claims["iss"] == Guardian.issuer
  end

  test "encode_and_sign(object, audience)" do
    { :ok, jwt, _ } = Guardian.encode_and_sign("thinger", "my_aud")

    { :ok, claims } = Guardian.decode_and_verify(jwt)
    assert claims["aud"] == "my_aud"
    assert claims["sub"] == "thinger"
    assert claims["iat"]
    assert claims["exp"] > claims["iat"]
    assert claims["iss"] == Guardian.issuer
  end

  test "encode_and_sign(object, audience, claims)" do
    { :ok, jwt, _ } = Guardian.encode_and_sign("thinger", "my_aud", some: "thing")

    { :ok, claims } = Guardian.decode_and_verify(jwt)
    assert claims["aud"] == "my_aud"
    assert claims["sub"] == "thinger"
    assert claims["iat"]
    assert claims["exp"] > claims["iat"]
    assert claims["iss"] == Guardian.issuer
    assert claims["some"] == "thing"
  end

  test "revoke" do
    {:ok, jwt, claims} = Guardian.encode_and_sign("thinger", "my_aud", some: "thing")
    assert Guardian.revoke!(jwt, claims) == :ok
  end

  test "refresh" do

    old_claims = Guardian.Claims.app_claims
    |> Map.put("iat", Guardian.Utils.timestamp - 100)
    |> Map.put("exp", Guardian.Utils.timestamp + 100)

    {:ok, jwt, claims} = Guardian.encode_and_sign("thinger", "my_aud", old_claims)
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
