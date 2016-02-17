defmodule Guardian.ClaimsTest do
  @moduledoc false
  use ExUnit.Case, async: true
  @tag timeout: 1000

  test "app_claims" do
    app_claims = Guardian.Claims.app_claims
    assert app_claims["iss"] == Guardian.issuer
    assert app_claims["iat"]
    assert app_claims["exp"] > app_claims["iat"]
    assert app_claims["jti"]
  end

  test "app_claims with other claims" do
    app_claims = Guardian.Claims.app_claims(%{"some" => "foo"})
    assert app_claims["some"] == "foo"
  end

  test "typ with nil" do
    claims = %{}
    assert Guardian.Claims.typ(claims, nil) == %{"typ" => "token"}
  end

  test "typ with an typ atom" do
    claims = %{}
    assert Guardian.Claims.typ(claims, :thing) == %{"typ" => "thing"}
  end

  test "typ with an typ string" do
    claims = %{}
    assert Guardian.Claims.typ(claims, "thing") == %{"typ" => "thing"}
  end

  test "aud with nil" do
    claims = %{}
    assert Guardian.Claims.aud(claims, nil) == %{"aud" => "MyApp"}
  end

  test "aud with an aud atom" do
    claims = %{}
    assert Guardian.Claims.aud(claims, :thing) == %{"aud" => "thing"}
  end

  test "aud with an aud string" do
    claims = %{}
    assert Guardian.Claims.aud(claims, "thing") == %{"aud" => "thing"}
  end

  test "sub with a sub atom" do
    claims = %{}
    assert Guardian.Claims.sub(claims, :thing) == %{"sub" => "thing"}
  end

  test "sub with a sub string" do
    claims = %{}
    assert Guardian.Claims.sub(claims, "thing") == %{"sub" => "thing"}
  end

  test "iat with nothing" do
    claims = %{}
    assert Guardian.Claims.iat(claims)["iat"]
  end

  test "iat with a timestamp" do
    claims = %{}
    assert Guardian.Claims.iat(claims, 15) == %{"iat" => 15}
  end

  test "ttl with nothing" do
    claims = %{}
    the_claims = Guardian.Claims.ttl(claims)
    assert the_claims["iat"]
    assert the_claims["exp"] == the_claims["iat"] + 24 * 60 * 60
  end

  test "ttl with extisting iat" do
    claims = %{"iat" => 10}
    expected = %{"iat" => 10, "exp" => 10 + 24 * 60 * 60}
    assert Guardian.Claims.ttl(claims) == expected
  end

  test "ttl with extisting iat & in minutes" do
    claims = %{"iat" => 10}
    expected = %{"iat" => 10, "exp" => 10 + 10 * 60}
    assert Guardian.Claims.ttl(claims, {10, :minutes}) == expected
  end

  test "ttl with extisting iat & in unknown units" do
    claims = %{"iat" => 10}
    assert_raise RuntimeError, "Unknown Units: decade", fn ->
      Guardian.Claims.ttl(claims, {1, :decade})
    end
  end

  test "encodes permissions into the claims" do
    claims = Guardian.Claims.permissions(%{}, default: [:read, :write])
    assert claims == %{"pem" => %{"default" => 3}}

    claims = Guardian.Claims.permissions(
      %{},
      other: [:other_read, :other_write]
    )
    assert claims == %{"pem" => %{"other" => 3}}
  end
end
