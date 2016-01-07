defmodule Guardian.Plug.EnsurePermissionTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias Guardian.Plug.EnsurePermissions

  defmodule TestHandler do
    def unauthorized(conn, _) do
      conn
      |> Plug.Conn.assign(:guardian_spec, :forbidden)
      |> Plug.Conn.send_resp(401, "Unauthorized")
    end
  end

  @expected_failure TestHandler
  @failure [handler: @expected_failure]

  test "does not call the on failure when the permissions are present" do
    opts = EnsurePermissions.init(@failure ++ [ default: [:read, :write] ])

    pems = Guardian.Permissions.to_value([:read, :write])
    claims = %{ "pem" => %{ "default" => pems } }

    expected_conn = conn(:get, "/get")
    |> Guardian.Plug.set_claims({ :ok, claims })
    |> Plug.Conn.fetch_query_params
    |> EnsurePermissions.call(opts)

    assert expected_conn.assigns[:guardian_spec] == nil
  end

  test "is invalid when all permissions that are requested are present are not there" do
    opts = EnsurePermissions.init(@failure ++ [ default: [:read, :write] ])

    pems = Guardian.Permissions.to_value([:read])
    claims = %{ "pem" => %{ "default" => pems } }

    expected_conn = conn(:get, "/get")
    |> Guardian.Plug.set_claims({ :ok, claims })
    |> Plug.Conn.fetch_query_params
    |> EnsurePermissions.call(opts)

    assert expected_conn.assigns[:guardian_spec] == :forbidden
  end

  test "is invalid when the claims do not include the perm key that is required" do
    opts = EnsurePermissions.init(@failure ++ [ default: [:read, :write] ])

    pems = Guardian.Permissions.to_value([:other_read], :other)
    claims = %{ "pem" => %{ "default" => pems } }

    expected_conn = conn(:get, "/get")
    |> Guardian.Plug.set_claims({ :ok, claims })
    |> Plug.Conn.fetch_query_params
    |> EnsurePermissions.call(opts)

    assert expected_conn.assigns[:guardian_spec] == :forbidden
  end

  test "is invalid when all permissions are not present" do
    opts = EnsurePermissions.init(@failure ++ [ default: [:read, :write], other: [:other_read] ])

    pems = Guardian.Permissions.to_value([:read, :write, :update, :delete], :default)
    other_pems = Guardian.Permissions.to_value([:other_write], :other)
    claims = %{ "pem" => %{ "default" => pems, "other" => other_pems } }

    expected_conn = conn(:get, "/get")
    |> Guardian.Plug.set_claims({ :ok, claims })
    |> Plug.Conn.fetch_query_params
    |> EnsurePermissions.call(opts)

    assert expected_conn.assigns[:guardian_spec] == :forbidden
  end

  test "is valid when all permissions are present" do
    opts = EnsurePermissions.init(@failure ++ [ default: [:read, :write], other: [:other_read] ])

    pems = Guardian.Permissions.to_value([:read, :write, :update, :delete], :default)
    other_pems = Guardian.Permissions.to_value([:other_read, :other_write], :other)
    claims = %{ "pem" => %{ "default" => pems, "other" => other_pems } }

    expected_conn = conn(:get, "/get")
    |> Guardian.Plug.set_claims({ :ok, claims })
    |> Plug.Conn.fetch_query_params
    |> EnsurePermissions.call(opts)

    assert expected_conn.assigns[:guardian_spec] == nil
  end

  test "halts the connection" do
    opts = EnsurePermissions.init(@failure ++ [ default: [:read, :write], other: [:other_read] ])

    pems = Guardian.Permissions.to_value([:read, :write, :update, :delete], :default)
    other_pems = Guardian.Permissions.to_value([:other_write], :other)
    claims = %{ "pem" => %{ "default" => pems, "other" => other_pems } }

    expected_conn = conn(:get, "/get")
    |> Guardian.Plug.set_claims({ :ok, claims })
    |> Plug.Conn.fetch_query_params
    |> EnsurePermissions.call(opts)

    assert expected_conn.halted == true
  end
end
