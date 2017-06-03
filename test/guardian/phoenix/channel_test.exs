defmodule Guardian.Phoenix.ChannelTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Phoenix.ChannelTest

  @endpoint __MODULE__.Endpoint

  @resource %{id: "bobby"}

  setup do
    impl = __MODULE__.Impl
    {:ok, token, claims} = Guardian.encode_and_sign(impl, @resource)

    {:ok,
      socket: socket("some:room", %{some: :assign}),
      channel_mod: __MODULE__.MyChannel,
      impl: impl,
      token: token,
      claims: claims
    }
  end

  test "signs in the user", ctx do
    assert {:ok, params, socket} =
      apply(ctx.channel_mod, :join, ["room", %{"guardian_token" => ctx.token}, ctx.socket])

    assert Guardian.Phoenix.Socket.current_token(socket) == ctx.token
    assert Guardian.Phoenix.Socket.current_claims(socket) == ctx.claims
    assert Guardian.Phoenix.Socket.current_resource(socket) == @resource

    assert params[:claims] == ctx.claims
    assert params[:token] == ctx.token
    assert params[:resource] == @resource
  end

  test "does not assign the user", ctx do
    assert {:ok, params, socket} = apply(ctx.channel_mod, :join, ["room", %{}, ctx.socket])

    refute Guardian.Phoenix.Socket.current_token(socket)
    refute Guardian.Phoenix.Socket.current_claims(socket)
    refute Guardian.Phoenix.Socket.current_resource(socket)

    refute params[:claims]
    refute params[:token]
    refute params[:resource]
  end
end
