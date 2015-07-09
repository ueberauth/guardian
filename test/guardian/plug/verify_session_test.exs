defmodule Guardian.Plug.VerifySessionTest do
  use ExUnit.Case, async: true
  use Plug.Test
  import Guardian.TestHelper

  setup do
    conn = conn_with_fetched_session(conn(:get, "/"))
    claims = Guardian.Claims.app_claims(%{ sub: "user", aud: "aud" })
    { :ok, jwt } = Joken.encode(claims)
    { :ok, conn: conn, jwt: jwt, claims: claims }
  end

  test "with no JWT in the session at a default location", context do
    conn = Guardian.Plug.VerifySession.call(context.conn, [])
    assert conn.assigns[Guardian.Keys.claims_key] == nil
    assert conn.assigns[Guardian.Keys.jwt_key] == nil
  end

  test "with no JWT in the session at a specified location", context do
    conn = Guardian.Plug.VerifySession.call(context.conn, key: :secret)
    assert conn.assigns[Guardian.Keys.claims_key(:secret)] == nil
    assert conn.assigns[Guardian.Keys.jwt_key(:secret)] == nil
  end

  test "with a valid JWT in the session at the default location", context do
    the_conn = context.conn |> Plug.Conn.put_session(Guardian.Keys.base_key(:default), context.jwt)
    conn = Guardian.Plug.VerifySession.call(the_conn, [])
    assert conn.assigns[Guardian.Keys.claims_key] == { :ok, context.claims }
    assert conn.assigns[Guardian.Keys.jwt_key] == context.jwt
  end

  test "with a valid JWT in the session at a specified location", context do
    the_conn = context.conn |> Plug.Conn.put_session(Guardian.Keys.base_key(:secret), context.jwt)
    conn = Guardian.Plug.VerifySession.call(the_conn, key: :secret)
    assert conn.assigns[Guardian.Keys.claims_key(:secret)] == { :ok, context.claims }
    assert conn.assigns[Guardian.Keys.jwt_key(:secret)] == context.jwt
  end

  test "with an existing session in another location", context do
    the_conn = context.conn
    |> Plug.Conn.put_session(Guardian.Keys.base_key(:default), context.jwt)
    |> Plug.Conn.assign(Guardian.Keys.claims_key, context.claims)
    |> Plug.Conn.assign(Guardian.Keys.jwt_key, context.jwt)
    |> Plug.Conn.put_session(Guardian.Keys.base_key(:secret), context.jwt)

    conn = Guardian.Plug.VerifySession.call(the_conn, key: :secret)
    assert conn.assigns[Guardian.Keys.claims_key(:secret)] == { :ok, context.claims }
    assert conn.assigns[Guardian.Keys.jwt_key(:secret)] == context.jwt
  end
end
