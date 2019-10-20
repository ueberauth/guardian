defmodule Guardian.Plug.EnsureAuthenticatedTest do
  @moduledoc false

  use Plug.Test
  use ExUnit.Case

  alias Guardian.Plug.EnsureAuthenticated

  defmodule Handler do
    @moduledoc false

    import Plug.Conn
    @behaviour Guardian.Plug.ErrorHandler

    @impl Guardian.Plug.ErrorHandler
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

    def resource_from_claims(%{"sub" => id}), do: {:ok, %{id: id}}
  end

  @resource %{id: "bobby"}

  setup do
    impl = Impl
    handler = Handler
    {:ok, token, claims} = Impl.encode_and_sign(@resource)
    {:ok, %{claims: claims, conn: conn(:get, "/"), token: token, impl: impl, handler: handler}}
  end

  describe "with no authenticated token" do
    test "returns an error", ctx do
      conn = EnsureAuthenticated.call(ctx.conn, module: ctx.impl, error_handler: ctx.handler)
      assert {401, _, "{:unauthenticated, :unauthenticated}"} = sent_resp(conn)
      assert conn.halted
    end

    test "does not halt conn when option is set to false", ctx do
      conn = EnsureAuthenticated.call(ctx.conn, module: ctx.impl, error_handler: ctx.handler, halt: false)
      assert {401, _, "{:unauthenticated, :unauthenticated}"} = sent_resp(conn)
      refute conn.halted
    end
  end

  describe "with an authenticated token" do
    setup ctx do
      conn =
        ctx.conn
        |> Guardian.Plug.put_current_token(ctx.token, [])
        |> Guardian.Plug.put_current_claims(ctx.claims, [])

      {:ok, %{conn: conn}}
    end

    test "allows the plug to continue", ctx do
      conn = EnsureAuthenticated.call(ctx.conn, module: ctx.impl, error_handler: ctx.handler)
      refute conn.halted
      refute conn.status == 401
    end

    test "rejects when claims to not match", ctx do
      conn =
        EnsureAuthenticated.call(
          ctx.conn,
          module: ctx.impl,
          error_handler: ctx.handler,
          claims: %{no: "access"}
        )

      assert conn.halted
      assert conn.status == 401
      assert {401, _, "{:unauthenticated, :no}"} = sent_resp(conn)
    end
  end
end
