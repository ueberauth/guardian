defmodule Guardian.Plug.VerifyCookieTest do
  @moduledoc false

  import Plug.Test
  import Plug.Conn

  alias Guardian.Plug.Pipeline
  alias Guardian.Plug.VerifyCookie
  alias Guardian.Plug.VerifySession

  use ExUnit.Case, async: true

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
    impl = __MODULE__.Impl
    handler = __MODULE__.Handler
    {:ok, token, claims} = __MODULE__.Impl.encode_and_sign(@resource, %{}, token_type: "refresh")
    {:ok, %{claims: claims, conn: conn(:get, "/"), token: token, impl: impl, handler: handler}}
  end

  test "with no cookies fetched it does nothing", ctx do
    conn = VerifyCookie.call(ctx.conn, [])
    refute conn.halted
    refute Guardian.Plug.current_token(conn, [])
    refute Guardian.Plug.current_claims(conn, [])
  end

  describe "with fetched cookies that are empty" do
    setup %{conn: conn} do
      conn = fetch_cookies(conn)
      {:ok, %{conn: conn}}
    end

    test "it does nothing", ctx do
      conn = VerifyCookie.call(ctx.conn, [])
      refute conn.halted
      refute Guardian.Plug.current_token(conn, [])
      refute Guardian.Plug.current_claims(conn, [])
    end
  end

  describe "with fetched cookies that are not empty" do
    setup %{conn: conn, token: token, impl: impl, handler: handler} do
      conn =
        conn
        |> put_req_cookie("guardian_default_token", token)
        |> fetch_cookies()
        |> Pipeline.put_module(impl)
        |> Pipeline.put_error_handler(handler)

      {:ok, %{conn: conn}}
    end

    test "with an existing token already found", ctx do
      conn =
        ctx.conn
        |> Guardian.Plug.put_current_token(ctx.token)
        |> Guardian.Plug.put_current_claims(ctx.claims)

      conn = VerifyCookie.call(conn, [])
      refute conn.halted
      assert Guardian.Plug.current_token(conn, []) == ctx.token
      assert Guardian.Plug.current_claims(conn, []) == ctx.claims
    end

    test "with an incorrect token type", ctx do
      conn = VerifyCookie.call(ctx.conn, exchange_from: "access")
      assert conn.halted
      assert {401, _, "{:invalid_token, :invalid_token_type}"} = sent_resp(conn)
    end

    test "does not halt conn when option is set to false", ctx do
      conn = VerifyCookie.call(ctx.conn, exchange_from: "access", halt: false)
      refute conn.halted
      assert {401, _, "{:invalid_token, :invalid_token_type}"} = sent_resp(conn)
    end

    test "with no existing token found", ctx do
      conn = VerifyCookie.call(ctx.conn, [])

      refute conn.halted
      refute Guardian.Plug.current_token(conn, []) == ctx.token
      refute Guardian.Plug.current_claims(conn, []) == ctx.claims

      new_t = Guardian.Plug.current_token(conn, [])
      new_c = Guardian.Plug.current_claims(conn, [])

      assert new_c["typ"] == "access"
      refute new_t == ctx.token
    end

    test "in a different location", ctx do
      conn =
        :get
        |> conn("/")
        |> put_req_cookie("guardian_secret_token", ctx.token)
        |> fetch_cookies()
        |> Pipeline.put_module(ctx.impl)
        |> Pipeline.put_error_handler(ctx.handler)

      conn = VerifyCookie.call(conn, encode_from: "refresh", key: :secret)

      refute conn.halted
      refute Guardian.Plug.current_token(conn, key: :secret) == ctx.token
      refute Guardian.Plug.current_claims(conn, key: :secret) == ctx.claims

      new_t = Guardian.Plug.current_token(conn, key: :secret)
      new_c = Guardian.Plug.current_claims(conn, key: :secret)

      assert new_c["typ"] == "access"
      refute new_t == ctx.token
    end
  end

  describe "with verify session" do
    setup %{conn: conn, impl: impl, handler: handler} do
      conn =
        conn
        |> Pipeline.put_module(impl)
        |> Pipeline.put_error_handler(handler)

      {:ok, %{conn: conn}}
    end

    test "will verify", ctx do
      :ets.new(:session, [:named_table, :public, read_concurrency: true])

      session_config = Plug.Session.init(store: :ets, key: "default", table: :session)

      old_conn =
        ctx.conn
        |> put_req_cookie("guardian_default_token", ctx.token)
        |> fetch_cookies()
        |> Plug.Session.call(session_config)
        |> Plug.Conn.fetch_session()
        |> VerifyCookie.call([])

      private = Map.put(ctx.conn.private, :plug_session, old_conn.private[:plug_session])

      new_conn =
        %{ctx.conn | private: private}
        |> Plug.Session.call(session_config)
        |> Plug.Conn.fetch_session()
        |> VerifySession.call([])

      refute new_conn.status == 401
    end
  end
end
