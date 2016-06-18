defmodule Guardian.Plug.EnsureAuthenticatedTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Plug.Test
  import Guardian.TestHelper

  alias Guardian.Plug.EnsureAuthenticated

  defmodule TestHandler do
    @moduledoc false

    def unauthenticated(conn, _) do
      conn
      |> Plug.Conn.assign(:guardian_spec, :unauthenticated)
      |> Plug.Conn.send_resp(401, "Unauthenticated")
    end
  end

  setup do
    conn = conn(:get, "/foo")
    {:ok, %{conn: conn}}
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

  test "validates claims and calls through if claims are ok", %{conn: conn} do
    claims = %{"typ" => "access", "sub" => "user1"}

    ensured_conn =
      conn
      |> Guardian.Plug.set_claims({:ok, claims})
      |> run_plug(EnsureAuthenticated, handler: TestHandler, typ: "access")

    refute must_authenticate?(ensured_conn)
  end

  test "it validates claims and fails if claims don't match", %{conn: conn} do
    claims = %{"aud" => "oauth", "sub" => "user1"}

    ensured_conn =
      conn
      |> Guardian.Plug.set_claims({:ok, claims})
      |> run_plug(EnsureAuthenticated, handler: TestHandler, typ: "access")

    assert must_authenticate?(ensured_conn)
  end

  test "doesn't call unauth when session for default key", %{conn: conn} do
    claims = %{"typ" => "access", "sub" => "user1"}

    ensured_conn =
      conn
      |> Guardian.Plug.set_claims({:ok, claims})
      |> run_plug(EnsureAuthenticated, handler: TestHandler)

    refute must_authenticate?(ensured_conn)
  end

  test "doesn't call unauthenticated when session for key", %{conn: conn} do
    claims = %{"typ" => "access", "sub" => "user1"}

    ensured_conn =
      conn
      |> Guardian.Plug.set_claims({:ok, claims}, :secret)
      |> run_plug(EnsureAuthenticated, handler: TestHandler, key: :secret)

    refute must_authenticate?(ensured_conn)
  end

  test "calls unauthenticated with no session for default key", %{conn: conn} do
    ensured_conn = run_plug(conn, EnsureAuthenticated, handler: TestHandler)

    assert must_authenticate?(ensured_conn)
  end

  test "calls unauthenticated when no session for key", %{conn: conn} do
    ensured_conn = run_plug(
      conn,
      EnsureAuthenticated,
      handler: TestHandler,
      key: :secret
    )

    assert must_authenticate?(ensured_conn)
  end

  test "it halts the connection", %{conn: conn} do
    ensured_conn = run_plug(
      conn,
      EnsureAuthenticated,
      handler: TestHandler,
      key: :secret
    )

    assert ensured_conn.halted
  end

  defp must_authenticate?(conn) do
    conn.assigns[:guardian_spec] == :unauthenticated
  end
end
