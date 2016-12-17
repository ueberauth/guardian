defmodule Guardian.Plug.EnsureResourceTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Plug.Test
  import ExUnit.CaptureLog
  import Guardian.TestHelper

  alias Guardian.Plug.EnsureResource

  defmodule TestHandler do
    @moduledoc false

    def no_resource(conn, _) do
      conn
      |> Plug.Conn.assign(:guardian_spec, :no_resource)
      |> Plug.Conn.send_resp(403, "Unauthorized")
    end
  end

  setup do
    conn = conn(:get, "/foo")
    {:ok, %{conn: conn}}
  end

  test "init/1 sets the handler option to the module that's passed in" do
    %{handler: handler_opts} = EnsureResource.init(handler: TestHandler)

    assert handler_opts == {TestHandler, :no_resource}
  end

  test "init/1 sets the handler option to the value of on_failure" do
    fun = fn ->
      %{handler: handler_opts} = EnsureResource.init(
        on_failure: {TestHandler, :custom_failure_method}
      )

      assert handler_opts == {TestHandler, :custom_failure_method}
    end

    assert capture_log([level: :warn], fun) =~ ":on_failure is deprecated"
  end

  test "init/1 defaults the handler option to Guardian.Plug.ErrorHandler" do
    %{handler: handler_opts} = EnsureResource.init %{}

    assert handler_opts == {Guardian.Plug.ErrorHandler, :no_resource}
  end

  test "init/1 with default options" do
    options = EnsureResource.init %{}

    assert options == %{
      handler: {Guardian.Plug.ErrorHandler, :no_resource},
      key: :default
    }
  end

  test "with a resource already set doesn't call no_resource for default key", %{conn: conn} do
    ensured_conn =
      conn
      |> Guardian.Plug.set_current_resource(:the_resource)
      |> run_plug(EnsureResource, handler: TestHandler)

    refute must_have_resource(ensured_conn)
  end

  test "with a resource already set doesn't call no_resource for key", %{conn: conn} do
    ensured_conn =
      conn
      |> Guardian.Plug.set_current_resource(:the_resource, :secret)
      |> run_plug(EnsureResource, handler: TestHandler, key: :secret)

    refute must_have_resource(ensured_conn)
  end

  test "with no resource set calls no_resource for default key", %{conn: conn} do
    ensured_conn = run_plug(
      conn,
      EnsureResource,
      handler: TestHandler
    )

    assert must_have_resource(ensured_conn)
  end

  test "with no resource set calls no_resource for key", %{conn: conn} do
    ensured_conn = run_plug(
      conn,
      EnsureResource,
      handler: TestHandler,
      key: :secret
    )

    assert must_have_resource(ensured_conn)
  end

  test "it halts the connection", %{conn: conn} do
    ensured_conn = run_plug(
      conn,
      EnsureResource,
      handler: TestHandler,
      key: :secret
    )

    assert ensured_conn.halted
  end

  defp must_have_resource(conn) do
    conn.assigns[:guardian_spec] == :no_resource
  end
end
