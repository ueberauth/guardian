defmodule Guardian.Plug.LoadResourceTest do
  @moduledoc false

  use Plug.Test
  use ExUnit.Case, async: true

  alias Guardian.Plug, as: GPlug
  alias GPlug.{LoadResource}

  @resource %{id: "bobby"}

  defmodule Handler do
    @moduledoc false

    import Plug.Conn

    def auth_error(conn, {type, reason}, _opts) do
      body = inspect({type, reason})
      send_resp(conn, 401, body)
    end
  end

  defmodule Impl do
    @moduledoc false

    use Guardian,
      otp_app: :guardian,
      token_module: Guardian.Support.TokenModule

    def subject_for_token(%{id: id}, _claims), do: {:ok, id}
    def subject_for_token(%{"id" => id}, _claims), do: {:ok, id}
    def subject_for_token(_, _), do: {:error, :cannot_serialize_resource}

    def resource_from_claims(%{"sub" => id}), do: {:ok, %{id: id}}
    def resource_from_claims(_), do: {:error, :not_found}
  end

  setup do
    impl = __MODULE__.Impl
    handler = __MODULE__.Handler
    {:ok, token, claims} = __MODULE__.Impl.encode_and_sign(@resource)
    {:ok, %{claims: claims, conn: conn(:get, "/"), token: token, impl: impl, handler: handler}}
  end

  describe "with no token" do
    test "it does nothing", ctx do
      conn =
        LoadResource.call(
          ctx.conn,
          module: ctx.impl,
          error_handler: ctx.handler,
          allow_blank: true
        )

      refute conn.status == 401
      refute conn.halted
    end

    test "it fails when allow_blank is not set", ctx do
      conn = LoadResource.call(ctx.conn, module: ctx.impl, error_handler: ctx.handler)
      assert {401, _, "{:no_resource_found, :no_resource_found}"} = sent_resp(conn)
      assert conn.halted
    end
  end

  describe "with a token but no resource that can be found" do
    setup %{conn: conn, token: token} do
      conn =
        conn
        |> GPlug.put_current_token(token, [])
        |> GPlug.put_current_claims(%{"no" => "sub"}, [])

      {:ok, conn: conn}
    end

    test "it fails", ctx do
      conn = LoadResource.call(ctx.conn, module: ctx.impl, error_handler: ctx.handler)
      assert {401, _, "{:no_resource_found, :not_found}"} = sent_resp(conn)
      assert conn.halted
    end
  end

  describe "with a token and found resource" do
    test "it lets the connection continue and adds the resource", ctx do
      conn =
        ctx.conn
        |> GPlug.put_current_token(ctx.token, [])
        |> GPlug.put_current_claims(ctx.claims, [])

      conn = LoadResource.call(conn, module: ctx.impl, error_handler: ctx.handler)

      refute conn.status == 401
      refute conn.halted

      assert @resource == GPlug.current_resource(conn, [])
    end
  end
end
