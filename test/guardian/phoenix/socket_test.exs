defmodule Guardian.Phoenix.SocketTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Phoenix.ChannelTest

  @endpoint __MODULE__.Endpoint

  @resource %{id: "bobby"}

  setup do
    impl = __MODULE__.Impl
    {:ok, token, claims} = Guardian.encode_and_sign(impl, @resource)

    {:ok,
     socket: socket("user_id", %{some: :assign}),
     socket_mod: __MODULE__.MySocket,
     impl: impl,
     token: token,
     claims: claims}
  end

  test "signs in the user", ctx do
    assert {:ok, socket} = ctx.socket_mod.connect(%{"guardian_token" => ctx.token}, ctx.socket)

    assert Guardian.Phoenix.Socket.current_token(socket) == ctx.token
    assert Guardian.Phoenix.Socket.current_claims(socket) == ctx.claims
    assert Guardian.Phoenix.Socket.current_resource(socket) == @resource
  end

  test "does not assign the user", ctx do
    assert :error = apply(ctx.socket_mod, :connect, [%{}, ctx.socket])
  end
end
