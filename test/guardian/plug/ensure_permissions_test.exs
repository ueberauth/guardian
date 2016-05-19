defmodule Guardian.Plug.EnsurePermissionTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Plug.Test
  import Guardian.TestHelper

  alias Guardian.Plug.EnsurePermissions

  defmodule TestHandler do
    @moduledoc false

    def unauthorized(conn, _) do
      conn
      |> Plug.Conn.assign(:guardian_spec, :forbidden)
      |> Plug.Conn.send_resp(401, "Unauthorized")
    end
  end

  setup do
    conn = conn(:get, "/foo")
    {:ok, %{conn: conn}}
  end

  test "doesnt call unauthorized when permissions are present", %{conn: conn} do
    pems = Guardian.Permissions.to_value([:read, :write])
    claims = %{"pem" => %{"default" => pems}}

    expected_conn =
      conn
      |> Guardian.Plug.set_claims({:ok, claims})
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsurePermissions, handler: TestHandler,
                  default: [:read, :write])

    refute unauthorized?(expected_conn)
  end

  test "is invalid when missing a requested permission", %{conn: conn} do
    pems = Guardian.Permissions.to_value([:read])
    claims = %{"pem" => %{"default" => pems}}

    expected_conn =
      conn
      |> Guardian.Plug.set_claims({:ok, claims})
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsurePermissions, handler: TestHandler,
                  default: [:read, :write])

    assert unauthorized?(expected_conn)
  end

  test "is invalid when claims don't include the pem key", %{conn: conn} do
    pems = Guardian.Permissions.to_value([:other_read], :other)
    claims = %{"pem" => %{"default" => pems}}

    expected_conn =
      conn
      |> Guardian.Plug.set_claims({:ok, claims})
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsurePermissions, handler: TestHandler,
                  default: [:read, :write])

    assert unauthorized?(expected_conn)
  end

  test "is invalid when all permissions are not present", %{conn: conn} do
    pems = Guardian.Permissions.to_value(
      [:read, :write, :update, :delete],
      :default
    )
    other_pems = Guardian.Permissions.to_value([:other_write], :other)
    claims = %{"pem" => %{"default" => pems, "other" => other_pems}}

    expected_conn =
      conn
      |> Guardian.Plug.set_claims({:ok, claims})
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsurePermissions, handler: TestHandler,
                  default: [:read, :write], other: [:other_read])

    assert unauthorized?(expected_conn)
  end

  test "is valid when all permissions are present", %{conn: conn} do
    pems = Guardian.Permissions.to_value(
      [:read, :write, :update, :delete],
      :default
    )

    other_pems = Guardian.Permissions.to_value(
      [:other_read, :other_write],
      :other
    )

    claims = %{"pem" => %{"default" => pems, "other" => other_pems}}

    expected_conn =
      conn
      |> Guardian.Plug.set_claims({:ok, claims})
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsurePermissions, handler: TestHandler,
                  default: [:read, :write], other: [:other_read])

    refute unauthorized?(expected_conn)
  end

  test "is invalid when non of the one_of permissions set is present", %{conn: conn} do
    pems = Guardian.Permissions.to_value(
      [:read, :write, :update, :delete],
      :default
    )

    other_pems = Guardian.Permissions.to_value(
      [:other_read, :other_write],
      :other
    )

    claims = %{"pem" => %{"admin" => pems, "special" => other_pems}}

    expected_conn =
      conn
      |> Guardian.Plug.set_claims({:ok, claims})
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsurePermissions, handler: TestHandler,
                  one_of: [%{other: [:other_read]}, %{default: [:read, :write]}])

    assert unauthorized?(expected_conn)
  end

  test "is valid when at least one_of the permissions set is present", %{conn: conn} do
    pems = Guardian.Permissions.to_value(
      [:read, :write, :update, :delete],
      :default
    )

    other_pems = Guardian.Permissions.to_value(
      [:other_read, :other_write],
      :other
    )

    claims = %{"pem" => %{"special" => other_pems, "default" => pems}}

    expected_conn =
      conn
      |> Guardian.Plug.set_claims({:ok, claims})
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsurePermissions, handler: TestHandler,
                  one_of: [%{other: [:other_read]}, %{default: [:read, :write]}])

    refute unauthorized?(expected_conn)
  end

  test "is valid one_of and permissions are a kw list", %{conn: conn} do
    pems = Guardian.Permissions.to_value(
      [:read, :write, :update, :delete],
      :default
    )

    other_pems = Guardian.Permissions.to_value(
      [:other_read, :other_write],
      :other
    )

    claims = %{"pem" => %{"special" => other_pems, "default" => pems}}
    expected_conn =
    conn
    |> Guardian.Plug.set_claims({:ok, claims})
    |> Plug.Conn.fetch_query_params
    |> run_plug(
      EnsurePermissions,
      handler: TestHandler,
      one_of: [default: [:read]]
    )

    refute unauthorized?(expected_conn)
  end

  test "halts the connection", %{conn: conn} do
    pems = Guardian.Permissions.to_value(
      [:read, :write, :update, :delete],
      :default
    )

    other_pems = Guardian.Permissions.to_value([:other_write], :other)
    claims = %{"pem" => %{"default" => pems, "other" => other_pems}}

    expected_conn =
      conn
      |> Guardian.Plug.set_claims({:ok, claims})
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsurePermissions, handler: TestHandler,
                  default: [:read, :write], other: [:other_read])

    assert expected_conn.halted
  end

  def unauthorized?(conn) do
    conn.assigns[:guardian_spec] == :forbidden
  end
end
