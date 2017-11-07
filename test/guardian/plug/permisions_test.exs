defmodule Guardian.Plug.PermisionsTest do
  @moduledoc false
  
  use Plug.Test
  use ExUnit.Case, async: true
  alias Guardian.Plug, as: GPlug
  alias GPlug.{Permisions, Pipeline}

  defmodule Impl do
    use Guardian, otp_app: :guardian,
                permissions: %{
                  user: [:read, :write],
                  profile: %{read: 0b1, write: 0b10}
                },
                token_module: Guardian.Support.TokenModule

    def subject_for_token(resource, _claims), do: {:ok, resource}
    def resource_from_claims(claims), do: {:ok, claims["sub"]}

    def build_claims(claims, _resource, opts) do
      encode_permissions_into_claims!(claims, Keyword.get(opts, :permissions))
    end

    use Guardian.Permissions.Bitwise
  end

  defmodule Handler do
    @moduledoc false

    import Plug.Conn

    def auth_error(conn, {type, reason}, _opts) do
      body = inspect({type, reason})
      send_resp(conn, 403, body)
    end
  end

  setup do
    claims =
      %{"sub" => "user:1"}
      |> Impl.build_claims(nil, permissions: %{user: [:read, :write], profile: [:read]})

    conn =
      :get
      |> conn("/")
      |> Pipeline.call(module: Impl, error_handler: Handler)
      |> GPlug.put_current_claims(claims)

    {:ok, %{conn: conn, claims: claims}}
  end

  test "it does not allow when permissions are missing from ensure", ctx do
    opts = Permisions.init(ensure: %{user: [:write, :read], profile: [:read, :write]})
    conn = Permisions.call(ctx.conn, opts)

    assert {403, _headers, body} = sent_resp(conn)
    assert body == "{:unauthorized, :unauthorized}"
    assert conn.halted
  end

  test "it does not allow when none of the one_of permissions match", ctx do
    opts = Permisions.init(one_of: [
      %{profile: [:write]},
      %{user: [:read], profile: [:write]},
    ])

    conn = Permisions.call(ctx.conn, opts)

    assert {403, _headers, body} = sent_resp(conn)
    assert body == "{:unauthorized, :unauthorized}"
    assert conn.halted
  end

  test "it allows the request when permissions from ensure match", ctx do
    opts = Permisions.init(ensure: %{user: [:read], profile: [:read]})
    conn = Permisions.call(ctx.conn, opts)

    refute conn.halted

    opts = Permisions.init(ensure: %{user: [:read]})
    conn = Permisions.call(ctx.conn, opts)

    refute conn.halted
  end

  test "it allows when one of the one of permissions from one_of match", ctx do
    opts = Permisions.init(one_of: [
      %{user: [:write]},
      %{profile: [:write]},
      %{user: [:read]},
    ])
    conn = Permisions.call(ctx.conn, opts)

    refute conn.halted

    opts = Permisions.init(one_of: [
      %{user: [:write]},
      %{profile: [:write]},
      %{profile: [:read]},
    ])
    conn = Permisions.call(ctx.conn, opts)

    refute conn.halted
  end

  test "when there is no logged in resource it fails" do
    conn = :get |> conn("/") |> Pipeline.call(module: Impl, error_handler: Handler)

    opts = Permisions.init(ensure: %{user: [:read], profile: [:read]})
    conn = Permisions.call(conn, opts)

    assert conn.halted
    assert {403, _headers, body} = sent_resp(conn)
    assert body == "{:unauthorized, :unauthorized}"
  end

  test "when looking in a different location with correct permissions", ctx do
    opts = Permisions.init(ensure: %{user: [:read], profile: [:read]}, key: :secret)
    conn =
      ctx.conn
      |> GPlug.put_current_claims(ctx.claims, key: :secret)
      |> Permisions.call(opts)

    refute conn.halted

    opts = Permisions.init(ensure: %{user: [:read]}, key: :secret)

    conn =
      ctx.conn
      |> GPlug.put_current_claims(ctx.claims, key: :secret)
      |> Permisions.call(opts)

    refute conn.halted
  end

  test "when looking in a different location with incorrect ensure permissions", ctx do
    opts = Permisions.init(ensure: %{user: [:read], profile: [:read]}, key: :secret)
    conn = Permisions.call(ctx.conn, opts)

    assert conn.halted
    assert {403, _headers, body} = sent_resp(conn)
    assert body == "{:unauthorized, :unauthorized}"
  end

  test "when looking in a different location with incorrect one_of permissions", ctx do
    opts = Permisions.init(one_of: [%{user: [:read]}], key: :secret)
    conn = Permisions.call(ctx.conn, opts)

    assert conn.halted
    assert {403, _headers, body} = sent_resp(conn)
    assert body == "{:unauthorized, :unauthorized}"
  end

  test "with no permissions specified", ctx do
    opts = Permisions.init([])
    conn = Permisions.call(ctx.conn, opts)
    refute conn.halted
  end
end