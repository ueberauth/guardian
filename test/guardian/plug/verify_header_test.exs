defmodule Guardian.Plug.VerifyHeaderTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias Guardian.Claims
  alias Guardian.Plug.VerifyHeader

  setup do
    config = Application.get_env(:guardian, Guardian)
    algo = hd(Keyword.get(config, :allowed_algos))
    secret = Keyword.get(config, :secret_key)

    jose_jws = %{"alg" => algo}
    jose_jwk = %{"kty" => "oct", "k" => :base64url.encode(secret)}
    claims = Claims.app_claims(%{ "sub" => "user", "aud" => "aud" })
    { _, jwt } = jose_jwk
                 |> JOSE.JWT.sign(jose_jws, claims)
                 |> JOSE.JWS.compact

    {
      :ok,
      conn: conn(:get, "/"),
      jwt: jwt,
      claims: claims,
      jose_jws: jose_jws,
      jose_jwk: jose_jwk,
      secret: secret
    }
  end

  test "with no JWT in the session at a default location", context do
    conn = VerifyHeader.call(context.conn, %{})
    assert Guardian.Plug.claims(conn) == {:error, :no_session}
    assert Guardian.Plug.current_token(conn) == nil
  end

  test "with no JWT in the session at a specified location", context do
    conn = VerifyHeader.call(context.conn, %{key: :secret})
    assert Guardian.Plug.claims(conn, :secret) == {:error,  :no_session}
    assert Guardian.Plug.current_token(conn, :secret) == nil
  end

  test "with a valid JWT in the session at the default location", context do
    the_conn = context.conn |> put_req_header("authorization", context.jwt)
    conn = VerifyHeader.call(the_conn, %{})
    assert Guardian.Plug.claims(conn) == { :ok, context.claims }
    assert Guardian.Plug.current_token(conn) == context.jwt
  end

  test "with a valid JWT in the session at a specified location", context do
    the_conn = context.conn |> put_req_header("authorization", context.jwt)
    conn = VerifyHeader.call(the_conn, %{key: :secret})
    assert Guardian.Plug.claims(conn, :secret) == { :ok, context.claims }
    assert Guardian.Plug.current_token(conn, :secret) == context.jwt
  end

  test "with an existing session in another location", context do
    the_conn = context.conn
               |> put_req_header("authorization", context.jwt)
               |> Guardian.Plug.set_claims(context.claims)
               |> Guardian.Plug.set_current_token(context.jwt)

    conn = VerifyHeader.call(the_conn, %{key: :secret})
    assert Guardian.Plug.claims(conn, :secret) == { :ok, context.claims }
    assert Guardian.Plug.current_token(conn, :secret) == context.jwt
  end

  test "with a realm specified", context do
    the_conn = put_req_header(
      context.conn,
      "authorization",
      "Bearer #{context.jwt}"
    )

    opts = VerifyHeader.init(realm: "Bearer")

    conn = VerifyHeader.call(the_conn, opts)
    assert Guardian.Plug.claims(conn) == { :ok, context.claims }
    assert Guardian.Plug.current_token(conn) == context.jwt
  end

  test "with a realm specified and multiple auth headers", context do
    claims2 = Claims.app_claims(%{ "sub" => "user2", "aud" => "aud2" })
    { _, jwt2 } = context.jose_jwk
                  |> JOSE.JWT.sign(context.jose_jws, claims2)
                  |> JOSE.JWS.compact

    the_conn = context.conn
               |> put_req_header("authorization", "Bearer #{context.jwt}")
               |> put_req_header("authorization", "Client #{jwt2}")

    opts = VerifyHeader.init(realm: "Client")

    conn = VerifyHeader.call(the_conn, opts)
    assert Guardian.Plug.claims(conn) == { :ok, claims2 }
    assert Guardian.Plug.current_token(conn) == jwt2
  end

  test "pulls different tokens into different locations", context do
    claims2 = Claims.app_claims(%{ "sub" => "user2", "aud" => "aud2" })
    { _, jwt2 } =context.jose_jwk
                  |> JOSE.JWT.sign(context.jose_jws, claims2)
                  |> JOSE.JWS.compact

    # Can't use the put_req_header here since it overrides previous values
    the_conn = %{context.conn | req_headers: [
        {"authorization", "Bearer #{context.jwt}"},
        {"authorization", "Client #{jwt2}"}
      ]
    }

    default_opts = VerifyHeader.init(realm: "Bearer")
    client_opts = VerifyHeader.init(realm: "Client", key: :client)

    conn = the_conn
           |> VerifyHeader.call(default_opts)
           |> VerifyHeader.call(client_opts)

    assert Guardian.Plug.claims(conn, :client) == { :ok, claims2 }
    assert Guardian.Plug.current_token(conn, :client) == jwt2
    assert Guardian.Plug.claims(conn) == { :ok, context.claims }
    assert Guardian.Plug.current_token(conn) == context.jwt
  end
end
