defmodule Guardian.Plug.EnsureSessionTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias Guardian.Keys
  alias Guardian.Plug.EnsureSession

  defmodule TestHandler do
    def unauthenticated(conn, _) do
      conn |> Plug.Conn.assign(:guardian_spec, :unauthenticated)
    end
  end

  @expected_failure { TestHandler, :unauthenticated }
  @failure [on_failure: @expected_failure]

  test "it requires an on_failure option" do
    assert_raise RuntimeError, fn ->
      EnsureSession.init([])
    end

    assert %{ on_failure: @expected_failure } == EnsureSession.init(@failure)
  end

  test "it does not call on failure when there is a session at the default location" do
    claims = %{ "aud" => "token", "sub" => "user1" }
    conn = conn(:get, "/foo") |> Plug.Conn.assign(Keys.claims_key, { :ok, claims })
    ensured_conn = EnsureSession.call(conn, @failure)
    assert ensured_conn.assigns[:guardian_spec] == nil
  end

  test "it does not call on failure when there is a session at the specific location" do
    claims = %{ "aud" => "token", "sub" => "user1" }
    conn = conn(:get, "/foo") |> Plug.Conn.assign(Keys.claims_key(:secret), { :ok, claims })
    ensured_conn = EnsureSession.call(conn, @failure ++ [ key: :secret ])
    assert ensured_conn.assigns[:guardian_spec] == nil
  end

  test "it calls the on_failiure function when there is no session at default" do
    conn = conn(:get, "/foo")
    ensured_conn = EnsureSession.call(conn, @failure)
    assert ensured_conn.assigns[:guardian_spec] == :unauthenticated
  end

  test "it calls the on_failiure function when there is no session at a specific location" do
    conn = conn(:get, "/foo")
    ensured_conn = EnsureSession.call(conn, @failure ++ [ key: :secret ])
    assert ensured_conn.assigns[:guardian_spec] == :unauthenticated
  end
end
