defmodule Guardian.Plug.EnsurePermissionTest do
  use ExUnit.Case, async: true
  use Plug.Test

  alias Guardian.Claims
  alias Guardian.Keys
  alias Guardian.Plug.EnsurePermissions
  alias Plug.Conn

  defmodule TestHandler do
    def forbidden(conn, _) do
      conn |> Plug.Conn.assign(:guardian_spec, :forbidden)
    end
  end

  @expected_failure { TestHandler, :forbidden }
  @failure [on_failure: @expected_failure]

  test "it requires an on_failure option" do
    assert_raise RuntimeError, fn ->
      EnsurePermissions.init([])
    end
  end

  test "does not call the on failure when the permissions are present" do
    opts = EnsurePermissions.init(@failure ++ [ default: [:read, :write] ])

    pems = Guardian.Permissions.to_value([:read, :write])
    claims = %{ pem: %{ default: pems } }

    expected_conn = conn(:get, "/get")
    |> Plug.Conn.assign(Keys.claims_key, { :ok, claims })
    |> Plug.Conn.fetch_query_params
    |> EnsurePermissions.call(opts)

    assert expected_conn.assigns[:guardian_spec] == nil
  end

  test "is invalid when all permissions that are requested are present are not there" do
    opts = EnsurePermissions.init(@failure ++ [ default: [:read, :write] ])

    pems = Guardian.Permissions.to_value([:read])
    claims = %{ pem: %{ default: pems } }

    expected_conn = conn(:get, "/get")
    |> Plug.Conn.assign(Keys.claims_key, { :ok, claims })
    |> Plug.Conn.fetch_query_params
    |> EnsurePermissions.call(opts)

    assert expected_conn.assigns[:guardian_spec] == :forbidden
  end

  test "is invalid when the claims do not include the perm key that is required" do
    opts = EnsurePermissions.init(@failure ++ [ default: [:read, :write] ])

    pems = Guardian.Permissions.to_value([:other_read], :other)
    claims = %{ pem: %{ default: pems } }

    expected_conn = conn(:get, "/get")
    |> Plug.Conn.assign(Keys.claims_key, { :ok, claims })
    |> Plug.Conn.fetch_query_params
    |> EnsurePermissions.call(opts)

    assert expected_conn.assigns[:guardian_spec] == :forbidden
  end

  test "is invalid when all permissions are not present" do
    opts = EnsurePermissions.init(@failure ++ [ default: [:read, :write], other: [:other_read] ])

    pems = Guardian.Permissions.to_value([:read, :write, :update, :delete], :default)
    other_pems = Guardian.Permissions.to_value([:other_write], :other)
    claims = %{ pem: %{ default: pems, other: other_pems } }

    expected_conn = conn(:get, "/get")
    |> Plug.Conn.assign(Keys.claims_key, { :ok, claims })
    |> Plug.Conn.fetch_query_params
    |> EnsurePermissions.call(opts)

    assert expected_conn.assigns[:guardian_spec] == :forbidden
  end

  test "is valid when all permissions are present" do
    opts = EnsurePermissions.init(@failure ++ [ default: [:read, :write], other: [:other_read] ])

    pems = Guardian.Permissions.to_value([:read, :write, :update, :delete], :default)
    other_pems = Guardian.Permissions.to_value([:other_read, :other_write], :other)
    claims = %{ pem: %{ default: pems, other: other_pems } }

    expected_conn = conn(:get, "/get")
    |> Plug.Conn.assign(Keys.claims_key, { :ok, claims })
    |> Plug.Conn.fetch_query_params
    |> EnsurePermissions.call(opts)

    assert expected_conn.assigns[:guardian_spec] == nil
  end
end
