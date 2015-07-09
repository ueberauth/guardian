defmodule Guardian.Plug.VerifyAuthorizationTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias Guardian.Claims
  alias Guardian.Keys
  alias Guardian.Plug.VerifyAuthorization
  alias Plug.Conn

  setup do
    claims = Claims.app_claims(%{ sub: "user", aud: "aud" })
    { :ok, jwt } = Joken.encode(claims)
    { :ok, conn: conn(:get, "/"), jwt: jwt, claims: claims }
  end

  test "with no JWT in the session at a default location", context do
    conn = VerifyAuthorization.call(context.conn, [])
    assert conn.assigns[Keys.claims_key] == nil
    assert conn.assigns[Keys.jwt_key] == nil
  end

  test "with no JWT in the session at a specified location", context do
    conn = VerifyAuthorization.call(context.conn, key: :secret)
    assert conn.assigns[Keys.claims_key(:secret)] == nil
    assert conn.assigns[Keys.jwt_key(:secret)] == nil
  end

  test "with a valid JWT in the session at the default location", context do
    the_conn = context.conn |> put_req_header("authorization", context.jwt)
    conn = VerifyAuthorization.call(the_conn, [])
    assert conn.assigns[Keys.claims_key] == { :ok, context.claims }
    assert conn.assigns[Keys.jwt_key] == context.jwt
  end

  test "with a valid JWT in the session at a specified location", context do
    the_conn = context.conn |> put_req_header("authorization", context.jwt)
    conn = VerifyAuthorization.call(the_conn, key: :secret)
    assert conn.assigns[Keys.claims_key(:secret)] == { :ok, context.claims }
    assert conn.assigns[Keys.jwt_key(:secret)] == context.jwt
  end

  test "with an existing session in another location", context do
    the_conn = context.conn
    |> put_req_header("authorization", context.jwt)
    |> Conn.assign(Keys.claims_key, context.claims)
    |> Conn.assign(Keys.jwt_key, context.jwt)

    conn = VerifyAuthorization.call(the_conn, key: :secret)
    assert conn.assigns[Keys.claims_key(:secret)] == { :ok, context.claims }
    assert conn.assigns[Keys.jwt_key(:secret)] == context.jwt
  end
end
