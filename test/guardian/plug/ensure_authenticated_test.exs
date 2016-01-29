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

  test "init/1 sets the handler option to the module that's passed in" do
    %{handler: handler_opts} = EnsureAuthenticated.init(handler: TestHandler)

    assert handler_opts == {TestHandler, :unauthenticated}
  end

  test "init/1 sets the handler option to the value of on_failure" do
    %{handler: handler_opts} = EnsureAuthenticated.init(
      on_failure: {TestHandler, :custom_failure_method}
    )

    assert handler_opts == {TestHandler, :custom_failure_method}
  end

  test "init/1 defaults the handler option to Guardian.Plug.ErrorHandler" do
    %{handler: handler_opts} = EnsureAuthenticated.init %{}

    assert handler_opts == {Guardian.Plug.ErrorHandler, :unauthenticated}
  end

  test "init/1 with default options" do
    options = EnsureAuthenticated.init %{}

    assert options == %{
      claims: %{},
      handler: {Guardian.Plug.ErrorHandler, :unauthenticated},
      key: :default
    }
  end

  test "init/1 uses all opts as claims except :on_failure, :key and :handler" do
    %{claims: claims} = EnsureAuthenticated.init(
      on_failure: {TestHandler, :some_method},
      key: :super_secret,
      handler: TestHandler,
      foo: "bar",
      another: "option"
    )

    assert claims == %{"foo" => "bar", "another" => "option"}
  end

  test "it validates claims and calls through if the claims are ok" do
    claims = %{ "aud" => "token", "sub" => "user1" }
    conn = :get |> conn("/foo") |> Guardian.Plug.set_claims({ :ok, claims })
    opts = EnsureAuthenticated.init(handler: TestHandler, aud: "token")
    ensured_conn = EnsureAuthenticated.call(conn, opts)
    refute must_authenticate?(ensured_conn)
  end

  test "it validates claims and fails if the claims do not match" do
    claims = %{ "aud" => "oauth", "sub" => "user1" }
    conn = :get |> conn("/foo") |> Guardian.Plug.set_claims({:ok, claims})
    opts = EnsureAuthenticated.init(handler: TestHandler, aud: "token")
    ensured_conn = EnsureAuthenticated.call(conn, opts)
    assert must_authenticate?(ensured_conn)
  end

  test "doesn't call unauthenticated when there's a session with default key" do
    claims = %{ "aud" => "token", "sub" => "user1" }
    conn = :get |> conn("/foo") |> Guardian.Plug.set_claims({ :ok, claims })
    opts = EnsureAuthenticated.init(handler: TestHandler)
    ensured_conn = EnsureAuthenticated.call(conn, opts)
    refute must_authenticate?(ensured_conn)
  end

  test "doesn't call unauthenticated when theres a session with specific key" do
    claims = %{ "aud" => "token", "sub" => "user1" }
    conn = :get
            |> conn("/foo")
            |> Guardian.Plug.set_claims({:ok, claims}, :secret)
    opts = EnsureAuthenticated.init(handler: TestHandler, key: :secret)
    ensured_conn = EnsureAuthenticated.call(conn, opts)
    refute must_authenticate?(ensured_conn)
  end

  test "calls handler's unauthenticated/2 with no session for default key" do
    conn = conn(:get, "/foo")
    opts = EnsureAuthenticated.init(handler: TestHandler)
    ensured_conn = EnsureAuthenticated.call(conn, opts)
    assert must_authenticate?(ensured_conn)
  end

  test "calls handler's unauthenticated/2 with no session for specific key" do
    conn = conn(:get, "/foo")
    opts = EnsureAuthenticated.init(handler: TestHandler, key: :secret)
    ensured_conn = EnsureAuthenticated.call(conn, opts)
    assert must_authenticate?(ensured_conn)
  end

  test "it halts the connection" do
    conn = conn(:get, "/foo")
    opts = EnsureAuthenticated.init(handler: TestHandler, key: :secret)
    ensured_conn = EnsureAuthenticated.call(conn, opts)
    assert ensured_conn.halted
  end

  defp must_authenticate?(conn) do
    conn.assigns[:guardian_spec] == :unauthenticated
  end
end
