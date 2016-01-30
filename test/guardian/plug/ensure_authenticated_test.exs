defmodule Guardian.Plug.EnsureAuthenticatedTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias Guardian.Plug.EnsureAuthenticated

  defmodule TestHandler do
    def unauthenticated(conn, _) do
      conn
      |> Plug.Conn.assign(:guardian_spec, :unauthenticated)
      |> Plug.Conn.send_resp(401, "Unauthenticated")
    end
  end

  @expected_failure TestHandler
  @failure %{ handler: {@expected_failure, :unauthenticated}}

  test "it validates claims and calls through if the claims are ok" do
    claims = %{ "aud" => "token", "sub" => "user1" }
    conn = :get |> conn("/foo") |> Guardian.Plug.set_claims({ :ok, claims })
    opts = EnsureAuthenticated.init(handler: @expected_failure, aud: "token")
    ensured_conn = EnsureAuthenticated.call(conn, opts)
    assert ensured_conn.assigns[:guardian_spec] == nil
  end

  test "it validates claims and fails if the claims do not match" do
    claims = %{ "aud" => "oauth", "sub" => "user1" }
    conn = :get |> conn("/foo") |> Guardian.Plug.set_claims({:ok, claims})
    opts = EnsureAuthenticated.init(handler: @expected_failure, aud: "token")
    ensured_conn = EnsureAuthenticated.call(conn, opts)
    assert ensured_conn.assigns[:guardian_spec] == :unauthenticated
  end

  test "it does not call on failure with a session at the default location" do
    claims = %{ "aud" => "token", "sub" => "user1" }
    conn = :get |> conn("/foo") |> Guardian.Plug.set_claims({ :ok, claims })
    ensured_conn = EnsureAuthenticated.call(conn, @failure)
    assert ensured_conn.assigns[:guardian_spec] == nil
  end

  test "it does not call on failure with a session at the specific location" do
    claims = %{ "aud" => "token", "sub" => "user1" }
    conn = :get
           |> conn("/foo")
           |> Guardian.Plug.set_claims({:ok, claims}, :secret)

    ensured_conn = EnsureAuthenticated.call(
      conn,
      %{handler: {@expected_failure, :unauthenticated}, key: :secret}
    )

    assert ensured_conn.assigns[:guardian_spec] == nil
  end

  test "it calls the handler unauthenticated with no session at default" do
    conn = conn(:get, "/foo")
    ensured_conn = EnsureAuthenticated.call(conn, @failure)
    assert ensured_conn.assigns[:guardian_spec] == :unauthenticated
  end

  test "it calls on_failiure function with no session at the location" do
    conn = conn(:get, "/foo")
    ensured_conn = EnsureAuthenticated.call(
      conn,
      %{
        handler: {@expected_failure, :unauthenticated},
        key: :secret
      }
    )

    assert ensured_conn.assigns[:guardian_spec] == :unauthenticated
  end

  test "it halts the connection" do
    conn = conn(:get, "/foo")
    ensured_conn = EnsureAuthenticated.call(
      conn,
      %{
        handler: {@expected_failure, :unauthenticated},
        key: :secret
      }
    )
    assert ensured_conn.halted
  end
end
