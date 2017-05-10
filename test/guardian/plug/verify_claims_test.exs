defmodule Guardian.Plug.VerifyClaimsTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Plug.Test
  import Guardian.TestHelper

  alias Guardian.Plug.VerifyClaims

  setup do
    conn = conn_with_fetched_session(conn(:get, "/"))
    claims = Guardian.Claims.app_claims(%{"sub" => "user", "aud" => "aud"})

    {
      :ok,
      conn: conn,
      claims: claims,
    }
  end

  test "with no Claims in the session at a default location", context do
    conn = run_plug(context.conn, VerifyClaims)
    assert Guardian.Plug.claims(conn) == {:error, :no_session}
    assert Guardian.Plug.current_token(conn) == nil
  end

  test "with no Claims in the session at a specified location", context do
    conn = run_plug(context.conn, VerifyClaims, %{key: :secret})
    assert Guardian.Plug.claims(conn, :secret) == {:error, :no_session}
    assert Guardian.Plug.current_token(conn, :secret) == nil
  end

  test "with valid Claims in the session at the default location", context do
    conn =
      context.conn
      |> Plug.Conn.put_session(Guardian.Keys.base_key(:default), context.claims)
      |> run_plug(VerifyClaims)

    assert Guardian.Plug.claims(conn) == {:ok, context.claims}
  end

  test "with valid Claims in the session at a specified location", context do
    conn =
      context.conn
      |> Plug.Conn.put_session(Guardian.Keys.base_key(:secret), context.claims)
      |> run_plug(VerifyClaims, %{key: :secret})

    assert Guardian.Plug.claims(conn, :secret) == {:ok, context.claims}
  end

  test "with an existing session in another location", context do
    conn =
      context.conn
      |> Plug.Conn.put_session(Guardian.Keys.base_key(:default), context.claims)
      |> Guardian.Plug.set_claims(context.claims)
      |> Plug.Conn.put_session(Guardian.Keys.base_key(:secret), context.claims)
      |> run_plug(VerifyClaims, %{key: :secret})

    assert Guardian.Plug.claims(conn, :secret) == {:ok, context.claims}
  end
end
