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
    { :ok, jwt} = Joken.encode(claims)

    { :ok, %{
        claims: claims,
        jwt: jwt
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

  test "fails if the issuer is not correct" do
    claims = %{aud: "token", exp: Guardian.Utils.timestamp + 100_00, iat: Guardian.Utils.timestamp, iss: "not the issuer", sub: "User:1"}
    { :ok, jwt} = Joken.encode(claims)

    assert Guardian.decode_and_verify(jwt) == { :error, :invalid_issuer }
  end

  test "fails if the expiry has passed", context do
    { :ok, jwt } = Joken.encode(Dict.put(context.claims, "exp", Guardian.Utils.timestamp - 10))
    assert Guardian.decode_and_verify(jwt) == { :error, :token_expired }
  end

  test "it is invalid if the aud is incorrect", context do
    assert Guardian.decode_and_verify(context.jwt, %{ aud: "something_else"}) == { :error, :invalid_audience }
  end

  test "verify! with a jwt", context do
    assert Guardian.decode_and_verify!(context.jwt) == context.claims
  end

  test "verify! with a bad token", context do
    { :ok, jwt } = Joken.encode(Dict.put(context.claims, "exp", Guardian.Utils.timestamp - 10))

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

  test "mint(object, audience)" do
    { :ok, jwt, _ } = Guardian.encode_and_sign("thinger", "my_aud")

    { :ok, claims } = Guardian.decode_and_verify(jwt)
    assert claims["aud"] == "my_aud"
    assert claims["sub"] == "thinger"
    assert claims["iat"]
    assert claims["exp"] > claims["iat"]
    assert claims["iss"] == Guardian.issuer
  end

  test "mint(object, audience, claims)" do
    { :ok, jwt, _ } = Guardian.encode_and_sign("thinger", "my_aud", some: "thing")

    { :ok, claims } = Guardian.decode_and_verify(jwt)
    assert claims["aud"] == "my_aud"
    assert claims["sub"] == "thinger"
    assert claims["iat"]
    assert claims["exp"] > claims["iat"]
    assert claims["iss"] == Guardian.issuer
    assert claims["some"] == "thing"
  end
end
