defmodule Guardian.PlugTest do
  @moduledoc false
  require Plug.Test
  use ExUnit.Case, async: true
  use Plug.Test
  import Guardian.TestHelper

  setup do
    {:ok, %{conn: conn(:post, "/")}}
  end

  test "authenticated?", context do
    refute Guardian.Plug.authenticated?(context.conn)
    new_conn = Guardian.Plug.set_claims(
      context.conn,
      {:ok, %{"some" => "claim"}}
    )
    assert Guardian.Plug.authenticated?(new_conn)
  end

  test "authenticated? with a location", context do
    refute Guardian.Plug.authenticated?(context.conn, :secret)
    new_conn = Guardian.Plug.set_claims(
      context.conn,
      {:ok, %{"some" => "claim"}},
      :secret
    )
    assert Guardian.Plug.authenticated?(new_conn, :secret)
  end

  test "set_claims with no key", context do
    claims = {:ok, %{"some" => "claim"}}
    new_conn = Guardian.Plug.set_claims(context.conn, claims)

    assert Guardian.Plug.claims(new_conn) == claims
  end

  test "set_claims with a key", context do
    claims = {:ok, %{"some" => "claim"}}
    new_conn = Guardian.Plug.set_claims(context.conn, claims, :secret)
    assert Guardian.Plug.claims(new_conn, :secret) == claims
  end

  test "claims with no key and no value", context do
    assert Guardian.Plug.claims(context.conn) == {:error, :no_session}
  end

  test "claims with no key and a value", context do
    claims = %{"some" => "claim"}
    new_conn = Guardian.Plug.set_claims(context.conn, {:ok, claims})
    assert Guardian.Plug.claims(new_conn) == {:ok, claims}
  end

  test "claims with a key and no value", context do
    assert Guardian.Plug.claims(context.conn, :secret) == {:error, :no_session}
  end

  test "claims with a key and a value", context do
    claims = %{"some" => "claim"}
    new_conn = Guardian.Plug.set_claims(context.conn, {:ok, claims}, :secret)
    assert Guardian.Plug.claims(new_conn, :secret) == {:ok, claims}
  end

  test "set_current_resource with no key", context do
    resource = "thing"
    new_conn = Guardian.Plug.set_current_resource(context.conn, resource)
    assert Guardian.Plug.current_resource(new_conn) == "thing"
  end

  test "set_current_resource with key", context do
    resource = "thing"
    new_conn = Guardian.Plug.set_current_resource(
      context.conn,
      resource,
      :secret
    )
    assert Guardian.Plug.current_resource(new_conn, :secret) == "thing"
  end

  test "current_resource with no key and no resource", context do
    assert Guardian.Plug.current_resource(context.conn) == nil
  end

  test "current_resource with no key and resource", context do
    resource = "thing"
    new_conn = Guardian.Plug.set_current_resource(context.conn, resource)
    assert Guardian.Plug.current_resource(new_conn) == resource
  end

  test "current_resource with key and resource", context do
    resource = "thing"
    new_conn = Guardian.Plug.set_current_resource(
      context.conn,
      resource,
      :secret
    )

    assert Guardian.Plug.current_resource(new_conn, :secret) == resource
  end

  test "current_resource with key and no resource", context do
    assert Guardian.Plug.current_resource(context.conn, :secret) == nil
  end

  test "set_current_token with no key", context do
    token = "token"
    new_conn = Guardian.Plug.set_current_token(context.conn, token)
    assert Guardian.Plug.current_token(new_conn) == "token"
  end

  test "set_current_token with key", context do
    token = "token"
    new_conn = Guardian.Plug.set_current_token(context.conn, token, :secret)
    assert Guardian.Plug.current_token(new_conn, :secret) == "token"
  end

  test "current_token with no key and no token", context do
    assert Guardian.Plug.current_token(context.conn) == nil
  end

  test "current_token with no key and token", context do
    token = "token"
    new_conn = Guardian.Plug.set_current_token(context.conn, token)
    assert Guardian.Plug.current_token(new_conn) == token
  end

  test "current_token with key and token", context do
    token = "token"
    new_conn = Guardian.Plug.set_current_token(context.conn, token, :secret)
    assert Guardian.Plug.current_token(new_conn, :secret) == token
  end

  test "current_token with key and no token", context do
    assert Guardian.Plug.current_token(context.conn, :secret) == nil
  end

  test "sign_out/1", context do
    conn = context.conn
           |> conn_with_fetched_session
           |> Guardian.Plug.sign_in(%{user: "here"}, :token)

    assert Guardian.Plug.current_resource(conn) == %{user: "here"}

    cleared_conn = conn
     |> Plug.Conn.put_session(Guardian.Keys.base_key(:default), "default jwt")
     |> Plug.Conn.put_session(Guardian.Keys.base_key(:secret), "secret jwt")
     |> Guardian.Plug.set_claims(%{claims: "yeah"})
     |> Guardian.Plug.set_claims(%{claims: "yeah"}, :secret)
     |> Guardian.Plug.set_current_resource("resource")
     |> Guardian.Plug.set_current_resource("resource", :secret)
     |> Guardian.Plug.set_current_token("token")
     |> Guardian.Plug.set_current_token("token", :secret)
     |> Guardian.Plug.sign_out

    assert Plug.Conn.get_session(
      cleared_conn,
      Guardian.Keys.base_key(:default)
    ) == nil

    assert Plug.Conn.get_session(
      cleared_conn, Guardian.Keys.base_key(:secret)
    ) == nil

    assert Guardian.Plug.claims(cleared_conn) == {:error, :no_session}
    assert Guardian.Plug.claims(cleared_conn, :secret) == {:error, :no_session}
    assert Guardian.Plug.current_resource(cleared_conn) == nil
    assert Guardian.Plug.current_resource(cleared_conn, :secret) == nil
    assert Guardian.Plug.current_token(cleared_conn) == nil
    assert Guardian.Plug.current_token(cleared_conn, :secret) == nil
  end

  test "sign_out/2", context do
    conn = conn_with_fetched_session(context.conn)

    cleared_conn = conn
     |> Guardian.Plug.set_claims({:ok, %{claims: "admin"}}, :secret)
     |> Guardian.Plug.set_claims({:ok, %{claims: "default"}})
     |> Guardian.Plug.set_current_resource("admin_resource", :secret)
     |> Guardian.Plug.set_current_resource("default_resource")
     |> Guardian.Plug.set_current_token("admin_token", :secret)
     |> Guardian.Plug.set_current_token("default_token")
     |> Guardian.Plug.sign_out(:secret)

    assert Guardian.Plug.claims(cleared_conn, :secret) == {:error, :no_session}
    assert Guardian.Plug.claims(cleared_conn) == {:ok, %{claims: "default"}}
    assert Guardian.Plug.current_resource(cleared_conn, :secret) == nil
    assert Guardian.Plug.current_resource(cleared_conn) == "default_resource"
    assert Guardian.Plug.current_token(cleared_conn, :secret) == nil
    assert Guardian.Plug.current_token(cleared_conn) == "default_token"
  end

  test "sign_in(object)", context do
    conn = context.conn
           |> conn_with_fetched_session
           |> Guardian.Plug.sign_in(%{user: "here"})

    assert Guardian.Plug.claims(conn) != nil
    assert Guardian.Plug.current_resource(conn) == %{user: "here"}
    assert Guardian.Plug.current_token(conn) != nil
  end

  test "sign_in(object, type)", context do
    conn = context.conn
           |> conn_with_fetched_session
           |> Guardian.Plug.sign_in(%{user: "here"})

    assert Guardian.Plug.claims(conn) != nil
    assert Guardian.Plug.current_resource(conn) == %{user: "here"}
    assert Guardian.Plug.current_token(conn) != nil

    jwt = Guardian.Plug.current_token(conn)
    {:ok, claims} = Guardian.decode_and_verify(jwt)

    assert claims["sub"]["user"] == "here"

    {:ok, claims} = Guardian.Plug.claims(conn)
    assert claims
  end

  test "sign_in(object, type, claims)", context do
    conn = context.conn
           |> conn_with_fetched_session
           |> Guardian.Plug.sign_in(%{user: "here"}, :token, here: "we are")

    assert Guardian.Plug.claims(conn) != nil
    assert Guardian.Plug.current_resource(conn) == %{user: "here"}
    assert Guardian.Plug.current_token(conn) != nil

    jwt = Guardian.Plug.current_token(conn)
    {:ok, claims} = Guardian.decode_and_verify(jwt)

    assert claims["sub"]["user"] == "here"
    assert claims["here"] == "we are"
    assert claims["typ"] == "token"
  end


  test "api_sign_in(object) error", context do
    conn = context.conn
           |> Guardian.Plug.api_sign_in(%{error: :unknown})

    claims = Guardian.Plug.claims(conn)

    assert {:error, _reason} = claims
    assert Guardian.Plug.current_resource(conn) == nil
    assert Guardian.Plug.current_token(conn) == nil
  end

  test "api_sign_in(object)", context do
    conn = context.conn
           |> Guardian.Plug.api_sign_in(%{user: "here"})

    assert Guardian.Plug.claims(conn) != nil
    assert Guardian.Plug.current_resource(conn) == %{user: "here"}
    assert Guardian.Plug.current_token(conn) != nil
  end

  test "api_sign_in(object, type)", context do
    conn = context.conn
           |> Guardian.Plug.api_sign_in(%{user: "here"})

    assert Guardian.Plug.claims(conn) != nil
    assert Guardian.Plug.current_resource(conn) == %{user: "here"}
    assert Guardian.Plug.current_token(conn) != nil

    jwt = Guardian.Plug.current_token(conn)
    {:ok, claims} = Guardian.decode_and_verify(jwt)

    assert claims["sub"]["user"] == "here"

    {:ok, claims} = Guardian.Plug.claims(conn)
    assert claims
  end

  test "api_sign_in(object, type, claims)", context do
    conn = context.conn
     |> Guardian.Plug.api_sign_in(%{user: "here"}, :token, here: "we are")

    assert Guardian.Plug.claims(conn) != nil
    assert Guardian.Plug.current_resource(conn) == %{user: "here"}
    assert Guardian.Plug.current_token(conn) != nil

    jwt = Guardian.Plug.current_token(conn)
    {:ok, claims} = Guardian.decode_and_verify(jwt)

    assert claims["sub"]["user"] == "here"
    assert claims["here"] == "we are"
  end
end
