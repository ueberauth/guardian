defmodule Guardian.PlugTest do
  require Plug.Test
  use ExUnit.Case, async: true
  use Plug.Test

  setup do
    { :ok, %{ conn: conn(:post, "/") } }
  end

  test "set_claims with no key", context do
    claims = %{ some: "claim" }
    new_conn = Guardian.Plug.set_claims(context.conn, claims)

    assert new_conn.assigns[Guardian.Keys.claims_key(:default)] == claims
  end

  test "set_claims with a key", context do
    claims = %{ some: "claim" }
    new_conn = Guardian.Plug.set_claims(context.conn, claims, :secret)
    assert new_conn.assigns[Guardian.Keys.claims_key(:secret)] == claims
  end

  test "claims with no key and no value", context do
    assert Guardian.Plug.claims(context.conn) == { :error, :no_session }
  end

  test "claims with no key and a value", context do
    claims = %{ some: "claim" }
    new_conn = Plug.Conn.assign(context.conn, Guardian.Keys.claims_key(:default), { :ok, claims })
    assert Guardian.Plug.claims(new_conn) == { :ok, claims }
  end

  test "claims with a key and no value", context do
    assert Guardian.Plug.claims(context.conn, :secret) == { :error, :no_session }
  end

  test "claims with a key and a value", context do
    claims = %{ some: "claim" }
    new_conn = Plug.Conn.assign(context.conn, Guardian.Keys.claims_key(:secret), { :ok, claims })
    assert Guardian.Plug.claims(new_conn, :secret) == { :ok, claims }
  end

  test "set_current_resource with no key", context do
    resource = "thing"
    new_conn = Guardian.Plug.set_current_resource(context.conn, resource)
    assert new_conn.assigns[Guardian.Keys.resource_key(:default)] == "thing"
  end

  test "set_current_resource with key", context do
    resource = "thing"
    new_conn = Guardian.Plug.set_current_resource(context.conn, resource, :secret)
    assert new_conn.assigns[Guardian.Keys.resource_key(:secret)] == "thing"
  end

  test "current_resource with no key and no resource", context do
    assert Guardian.Plug.current_resource(context.conn) == nil
  end

  test "current_resource with no key and resource", context do
    resource = "thing"
    new_conn = Plug.Conn.assign(context.conn, Guardian.Keys.resource_key(:default), resource)
    assert Guardian.Plug.current_resource(new_conn) == resource
  end

  test "current_resource with key and resource", context do
    resource = "thing"
    new_conn = Plug.Conn.assign(context.conn, Guardian.Keys.resource_key(:secret), resource)
    assert Guardian.Plug.current_resource(new_conn, :secret) == resource
  end

  test "current_resource with key and no resource", context do
    assert Guardian.Plug.current_resource(context.conn, :secret) == nil
  end

  test "set_current_token with no key", context do
    token = "token"
    new_conn = Guardian.Plug.set_current_token(context.conn, token)
    assert new_conn.assigns[Guardian.Keys.jwt_key(:default)] == "token"
  end

  test "set_current_token with key", context do
    token = "token"
    new_conn = Guardian.Plug.set_current_token(context.conn, token, :secret)
    assert new_conn.assigns[Guardian.Keys.jwt_key(:secret)] == "token"
  end

  test "current_token with no key and no token", context do
    assert Guardian.Plug.current_token(context.conn) == nil
  end

  test "current_token with no key and token", context do
    token = "token"
    new_conn = Plug.Conn.assign(context.conn, Guardian.Keys.jwt_key(:default), token)
    assert Guardian.Plug.current_token(new_conn) == token
  end

  test "current_token with key and token", context do
    token = "token"
    new_conn = Plug.Conn.assign(context.conn, Guardian.Keys.jwt_key(:secret), token)
    assert Guardian.Plug.current_token(new_conn, :secret) == token
  end

  test "current_token with key and no token", context do
    assert Guardian.Plug.current_token(context.conn, :secret) == nil
  end

  # TODO work out how to test with plugs
  # test "sign_out/1", context do
  #   cleared_conn = context.conn
  #   |> Plug.Conn.assign(Guardian.Keys.claims_key(:default), %{ claims: "yeah" })
  #   |> Plug.Conn.assign(Guardian.Keys.claims_key(:secret), %{ claims: "yeah" })
  #   |> Plug.Conn.assign(Guardian.Keys.resource_key(:default), "resource")
  #   |> Plug.Conn.assign(Guardian.Keys.resource_key(:secret), "resource")
  #   |> Plug.Conn.assign(Guardian.Keys.jwt_key(:default), "token")
  #   |> Plug.Conn.assign(Guardian.Keys.jwt_key(:secret), "token")
  #   |> Guardian.Plug.sign_out

  #   assert cleared_conn.assigns[Guardian.Keys.claims_key(:default)] == nil
  #   assert cleared_conn.assigns[Guardian.Keys.claims_key(:secret)] == nil
  #   assert cleared_conn.assigns[Guardian.Keys.resource_key(:default)] == nil
  #   assert cleared_conn.assigns[Guardian.Keys.resource_key(:secret)] == nil
  #   assert cleared_conn.assigns[Guardian.Keys.jwt_key(:default)] == nil
  #   assert cleared_conn.assigns[Guardian.Keys.jwt_key(:secret)] == nil
  # end

  # test "sign_out/2", context do
  # end

  # test "sign_in(object)", context do
  # end

  # test "sign_in(object, type)", context do
  # end

  # test "sign_in(object, claims)", context do
  # end
end

