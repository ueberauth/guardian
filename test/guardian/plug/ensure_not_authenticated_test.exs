defmodule Guardian.Plug.EnsureNotAuthenticatedTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias Guardian.Plug.EnsureNotAuthenticated

  defmodule TestHandler do
    def authenticated(conn, _) do
      conn
      |> Plug.Conn.assign(:guardian_spec, :authenticated)
      |> Plug.Conn.send_resp(401, "Authenticated")
    end
  end

  test "init/1 sets the handler option to the module that's passed in" do
    %{handler: handler_opts} = EnsureNotAuthenticated.init(handler: TestHandler)

    assert handler_opts == {TestHandler, :authenticated}
  end

  test "init/1 defaults the handler option to Guardian.Plug.ErrorHandler" do
    %{handler: handler_opts} = EnsureNotAuthenticated.init %{}

    assert handler_opts == {Guardian.Plug.ErrorHandler, :authenticated}
  end

  test "init/1 with default options" do
    options = EnsureNotAuthenticated.init %{}

    assert options == %{
      claims: %{},
      handler: {Guardian.Plug.ErrorHandler, :authenticated},
      key: :default
    }
  end

  test "it validates claims and calls through if the claims are ok" do
    claims = %{ "aud" => "token", "sub" => "user1" }
    conn = :get |> conn("/foo") |> Guardian.Plug.set_claims({ :ok, claims })
    opts = EnsureNotAuthenticated.init(handler: TestHandler, aud: "token")
    ensured_conn = EnsureNotAuthenticated.call(conn, opts)
    assert must_authenticate?(ensured_conn)
  end

  test "it validates claims and fails if the claims do not match" do
    claims = %{ "aud" => "oauth", "sub" => "user1" }
    conn = :get |> conn("/foo") |> Guardian.Plug.set_claims({:ok, claims})
    opts = EnsureNotAuthenticated.init(handler: TestHandler, aud: "token")
    ensured_conn = EnsureNotAuthenticated.call(conn, opts)
    refute must_authenticate?(ensured_conn)
  end

  test "doesn't call unauthenticated when there's a session with default key" do
    claims = %{ "aud" => "token", "sub" => "user1" }
    conn = :get |> conn("/foo") |> Guardian.Plug.set_claims({ :ok, claims })
    opts = EnsureNotAuthenticated.init(handler: TestHandler)
    ensured_conn = EnsureNotAuthenticated.call(conn, opts)
    assert must_authenticate?(ensured_conn)
  end

  test "doesn't call unauthenticated when theres a session with specific key" do
    claims = %{ "aud" => "token", "sub" => "user1" }
    conn = :get
            |> conn("/foo")
            |> Guardian.Plug.set_claims({:ok, claims}, :secret)
    opts = EnsureNotAuthenticated.init(handler: TestHandler, key: :secret)
    ensured_conn = EnsureNotAuthenticated.call(conn, opts)
    assert must_authenticate?(ensured_conn)
  end

  test "calls handler's unauthenticated/2 with no session for default key" do
    conn = conn(:get, "/foo")
    opts = EnsureNotAuthenticated.init(handler: TestHandler)
    ensured_conn = EnsureNotAuthenticated.call(conn, opts)
    refute must_authenticate?(ensured_conn)
  end

  test "calls handler's unauthenticated/2 with no session for specific key" do
    conn = conn(:get, "/foo")
    opts = EnsureNotAuthenticated.init(handler: TestHandler, key: :secret)
    ensured_conn = EnsureNotAuthenticated.call(conn, opts)
    refute must_authenticate?(ensured_conn)
  end

  test "it halts the connection" do
    conn = conn(:get, "/foo")
    opts = EnsureNotAuthenticated.init(handler: TestHandler, key: :secret)
    ensured_conn = EnsureNotAuthenticated.call(conn, opts)
    refute ensured_conn.halted
  end

  defp must_authenticate?(conn) do
    conn.assigns[:guardian_spec] == :authenticated
  end
end
