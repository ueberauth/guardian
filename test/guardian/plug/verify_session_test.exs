defmodule Guardian.Plug.VerifySessionTest do
  use ExUnit.Case, async: true
  use Plug.Test
  import Guardian.TestHelper

  setup do
    config = Application.get_env(:guardian, Guardian)
    algo = hd(Keyword.get(config, :allowed_algos))
    secret = Keyword.get(config, :secret_key)

    jose_jws = %{"alg" => algo}
    jose_jwk = %{"kty" => "oct", "k" => :base64url.encode(secret)}

    conn = conn_with_fetched_session(conn(:get, "/"))
    claims = Guardian.Claims.app_claims(%{"sub" => "user", "aud" => "aud"})

    { _, jwt } = jose_jwk
                  |> JOSE.JWT.sign(jose_jws, claims)
                  |> JOSE.JWS.compact

    {
      :ok,
      conn: conn,
      jwt: jwt,
      claims: claims,
      jose_jwk: jose_jwk,
      jose_jws: jose_jws
    }
  end

  test "with no JWT in the session at a default location", context do
    conn = Guardian.Plug.VerifySession.call(context.conn, %{})
    assert Guardian.Plug.claims(conn) == {:error, :no_session}
    assert Guardian.Plug.current_token(conn) == nil
  end

  test "with no JWT in the session at a specified location", context do
    conn = Guardian.Plug.VerifySession.call(context.conn, %{key: :secret})
    assert Guardian.Plug.claims(conn, :secret) == {:error, :no_session}
    assert Guardian.Plug.current_token(conn, :secret) == nil
  end

  test "with a valid JWT in the session at the default location", context do
    the_conn = context.conn
      |> Plug.Conn.put_session(Guardian.Keys.base_key(:default), context.jwt)

    conn = Guardian.Plug.VerifySession.call(the_conn, %{})
    assert Guardian.Plug.claims(conn) == { :ok, context.claims }
    assert Guardian.Plug.current_token(conn) == context.jwt
  end

  test "with a valid JWT in the session at a specified location", context do
    the_conn = context.conn
      |> Plug.Conn.put_session(Guardian.Keys.base_key(:secret), context.jwt)
    conn = Guardian.Plug.VerifySession.call(the_conn, %{key: :secret})
    assert Guardian.Plug.claims(conn, :secret) == {:ok, context.claims}
    assert Guardian.Plug.current_token(conn, :secret) == context.jwt
  end

  test "with an existing session in another location", context do
    the_conn = context.conn
     |> Plug.Conn.put_session(Guardian.Keys.base_key(:default), context.jwt)
     |> Guardian.Plug.set_claims(context.claims)
     |> Guardian.Plug.set_current_token(context.jwt)
     |> Plug.Conn.put_session(Guardian.Keys.base_key(:secret), context.jwt)

    conn = Guardian.Plug.VerifySession.call(the_conn, %{key: :secret})
    assert Guardian.Plug.claims(conn, :secret) == {:ok, context.claims}
    assert Guardian.Plug.current_token(conn, :secret) == context.jwt
  end
end
