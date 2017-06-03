defmodule Guardian.Phoenix.ControllerTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Plug.Test

  @resource %{id: "bobby"}

  setup do
    router = __MODULE__.Router
    impl = __MODULE__.Impl
    conn =
      :get
      |> conn("/things")
      |> Guardian.Plug.Pipeline.call(module: impl)

    {:ok, token, claims} = Guardian.encode_and_sign(impl, @resource)

    {:ok, %{conn: conn, router: router, impl: impl, token: token, claims: claims}}
  end

  test "it passes nil when no user is logged in", ctx do
    conn = apply(ctx.router, :call, [ctx.conn, []])
    expected_response = %{"resource" => nil, "claims" => nil} |> Poison.encode!()
    assert {200, _, ^expected_response} = sent_resp(conn)
  end

  test "it passes the resource and claims when logged in", ctx do
    conn =
      ctx.conn
      |> Guardian.Plug.put_current_token(ctx.token)
      |> Guardian.Plug.put_current_resource(@resource)
      |> Guardian.Plug.put_current_claims(ctx.claims)

    conn = apply(ctx.router, :call, [conn, []])

    expected_response = %{"resource" => @resource, "claims" => ctx.claims} |> Poison.encode!()
    assert {200, _, ^expected_response} = sent_resp(conn)
  end
end
