defmodule Guardian.Plug.SlidingCookieTest do
  @moduledoc false

  use Plug.Test

  alias Guardian.Plug.Pipeline
  alias Guardian.Plug.SlidingCookie

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

    def sliding_cookie(_claims, _resource, opts) do
      Enum.reduce(
        opts,
        {:ok, %{"new" => "claim"}},
        fn
          _, {:error, _reason} = error -> error
          {:fail_sliding_cookie, reason}, {:ok, _claims} -> {:error, reason}
          {:mutate_auth_time, :delete}, {:ok, claims} -> {:ok, Map.delete(claims, "auth_time")}
          {:mutate_auth_time, new_auth_time}, {:ok, claims} -> {:ok, Map.put(claims, "auth_time", new_auth_time)}
          _, {:ok, claims} -> {:ok, claims}
        end
      )
    end
  end

  @resource %{id: "bobby"}

  setup do
    impl = __MODULE__.Impl
    handler = __MODULE__.Handler

    conn =
      conn(:get, "/")
      |> Pipeline.put_module(impl)
      |> Pipeline.put_error_handler(handler)

    {:ok, token, claims} =
      __MODULE__.Impl.encode_and_sign(@resource, %{"exp" => Guardian.timestamp() + 60}, token_type: "refresh")

    {:ok, %{claims: claims, conn: conn, token: token, impl: impl, handler: handler}}
  end

  test "with no cookies fetched it does nothing", ctx do
    conn = SlidingCookie.call(ctx.conn, [])
    refute conn.halted
    assert conn === fetch_cookies(ctx.conn)
  end

  describe "with no sliding_window callback implementation" do
    setup ctx do
      conn =
        ctx.conn
        |> put_req_cookie("guardian_default_token", ctx.token)
        |> fetch_cookies()

      {:ok, %{ctx | conn: conn}}
    end

    test "conn is halted", ctx do
      conn =
        ctx.conn
        |> SlidingCookie.call(sliding_cookie: {60, :seconds}, fail_sliding_cookie: :not_implemented)

      assert conn.halted
    end

    test "conn is not halted when halt option is set to false", ctx do
      conn =
        ctx.conn
        |> SlidingCookie.call(sliding_cookie: {30, :seconds}, fail_sliding_cookie: :not_implemented, halt: false)

      refute conn.halted
    end
  end

  describe "with fetched cookies" do
    setup ctx do
      conn =
        ctx.conn
        |> fetch_cookies()

      {:ok, %{ctx | conn: conn}}
    end

    test "it does nothing", ctx do
      conn = SlidingCookie.call(ctx.conn, [])

      refute conn.halted
      assert conn === ctx.conn
    end
  end

  describe "with cookie and invalid token" do
    setup ctx do
      conn =
        ctx.conn
        |> put_req_cookie("guardian_default_token", "not a good one")
        |> fetch_cookies()

      {:ok, %{ctx | conn: conn}}
    end

    test "it does nothing", ctx do
      conn = SlidingCookie.call(ctx.conn, [])

      refute conn.halted
      assert conn === ctx.conn
    end
  end

  describe "with cookie and token after refresh threshold" do
    setup ctx do
      iat = Guardian.timestamp() - 110
      exp = Guardian.timestamp() + 10
      claims = %{"iat" => iat, "exp" => exp}
      {:ok, token, claims} = __MODULE__.Impl.encode_and_sign(@resource, claims, token_type: "refresh")

      conn =
        ctx.conn
        |> put_req_cookie("guardian_default_token", token)
        |> fetch_cookies()

      {:ok, %{ctx | conn: conn, claims: claims}}
    end

    test "it does nothing when claims verify fails", ctx do
      conn =
        ctx.conn
        |> SlidingCookie.call(sliding_cookie: {30, :seconds}, fail_verify_claims: true)

      assert conn === ctx.conn
    end

    test "it replaces cookie when claims verify succeeds", ctx do
      conn =
        ctx.conn
        |> SlidingCookie.call(sliding_cookie: {30, :seconds})

      refute conn.halted
      refute conn === ctx.conn
      assert %Plug.Conn{conn | cookies: %{}, resp_cookies: %{}} === %Plug.Conn{ctx.conn | cookies: %{}}
    end

    test "replacement cookie is valid and has specified new claims", ctx do
      conn =
        ctx.conn
        |> SlidingCookie.call(sliding_cookie: {30, :seconds})

      refute conn.halted
      refute conn === ctx.conn
      assert %Plug.Conn{conn | cookies: %{}, resp_cookies: %{}} === %Plug.Conn{ctx.conn | cookies: %{}}

      assert {:ok, %{"new" => "claim"}} =
               __MODULE__.Impl.decode_and_verify(conn.resp_cookies["guardian_default_token"].value)
    end
  end

  describe "with cookie and token before refresh threshold" do
    setup ctx do
      iat = Guardian.timestamp() - 60
      exp = Guardian.timestamp() + 60
      claims = %{"iat" => iat, "exp" => exp}
      {:ok, token, claims} = __MODULE__.Impl.encode_and_sign(@resource, claims, token_type: "refresh")

      conn =
        ctx.conn
        |> put_req_cookie("guardian_default_token", token)
        |> fetch_cookies()

      {:ok, %{ctx | conn: conn, claims: claims}}
    end

    test "it does nothing", ctx do
      conn =
        ctx.conn
        |> SlidingCookie.call(sliding_cookie: {30, :seconds})

      assert conn === ctx.conn
    end
  end

  describe "when auth_time set" do
    setup ctx do
      iat = Guardian.timestamp() - 110
      exp = Guardian.timestamp() + 10
      auth_time = 100

      claims = %{"iat" => iat, "exp" => exp, "auth_time" => auth_time}
      {:ok, token, claims} = __MODULE__.Impl.encode_and_sign(@resource, claims, token_type: "refresh")

      conn =
        ctx.conn
        |> put_req_cookie("guardian_default_token", token)
        |> fetch_cookies()

      {:ok, %{ctx | conn: conn, claims: claims}}
    end

    test "implementation module changes to auth_time are discarded", ctx do
      conn =
        ctx.conn
        |> SlidingCookie.call(sliding_cookie: {30, :seconds}, mutate_auth_time: 200)

      refute conn.halted
      refute conn === ctx.conn

      assert {:ok, %{"new" => "claim", "auth_time" => 100}} =
               __MODULE__.Impl.decode_and_verify(conn.resp_cookies["guardian_default_token"].value)

      conn =
        ctx.conn
        |> SlidingCookie.call(sliding_cookie: {30, :seconds}, mutate_auth_time: 100)

      refute conn.halted
      refute conn === ctx.conn

      assert {:ok, %{"new" => "claim", "auth_time" => 100}} =
               __MODULE__.Impl.decode_and_verify(conn.resp_cookies["guardian_default_token"].value)

      conn =
        ctx.conn
        |> SlidingCookie.call(sliding_cookie: {30, :seconds}, mutate_auth_time: :delete)

      refute conn.halted
      refute conn === ctx.conn

      assert {:ok, %{"new" => "claim", "auth_time" => 100}} =
               __MODULE__.Impl.decode_and_verify(conn.resp_cookies["guardian_default_token"].value)
    end
  end
end
