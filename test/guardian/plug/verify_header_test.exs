defmodule Guardian.Plug.VerifyHeaderTest do
  @moduledoc false

  use Plug.Test

  alias Guardian.Plug.Pipeline
  alias Guardian.Plug.VerifyHeader

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
    {:ok, token, claims} = __MODULE__.Impl.encode_and_sign(@resource)
    {:ok, %{claims: claims, conn: conn(:get, "/"), token: token, impl: impl, handler: handler}}
  end

  test "with no token" do
    conn = :get |> conn("/") |> VerifyHeader.call([])

    refute conn.status == 401
    assert Guardian.Plug.current_token(conn, []) == nil
    assert Guardian.Plug.current_claims(conn, []) == nil
  end

  test "it uses the module from options", ctx do
    conn =
      :get
      |> conn("/")
      |> put_req_header("authorization", ctx.token)
      |> VerifyHeader.call(module: ctx.impl)

    refute conn.status == 401
    assert Guardian.Plug.current_token(conn, []) == ctx.token
    assert Guardian.Plug.current_claims(conn, []) == ctx.claims
  end

  test "it finds the module from the pipeline", ctx do
    conn =
      :get
      |> conn("/")
      |> put_req_header("authorization", ctx.token)
      |> Pipeline.put_module(ctx.impl)
      |> VerifyHeader.call([])

    refute conn.status == 401
    assert Guardian.Plug.current_token(conn, []) == ctx.token
    assert Guardian.Plug.current_claims(conn, []) == ctx.claims
  end

  test "with an existing token on the connection it leaves it intact", ctx do
    {:ok, token, claims} = apply(ctx.impl, :encode_and_sign, [%{id: "jane"}])

    conn =
      :get
      |> conn("/")
      |> put_req_header("authorization", ctx.token)
      |> Guardian.Plug.put_current_token(token)
      |> Guardian.Plug.put_current_claims(claims)
      |> VerifyHeader.call([])

    refute conn.status == 401
    assert Guardian.Plug.current_token(conn) == token
    assert Guardian.Plug.current_claims(conn) == claims
  end

  test "with no module", ctx do
    assert_raise RuntimeError, "`module` not set in Guardian pipeline", fn ->
      :get
      |> conn("/")
      |> put_req_header("authorization", ctx.token)
      |> VerifyHeader.call([])
    end
  end

  test "with a key specified", ctx do
    conn =
      :get
      |> conn("/")
      |> put_req_header("authorization", ctx.token)
      |> VerifyHeader.call(module: ctx.impl, key: :secret)

    refute Guardian.Plug.current_token(conn)
    refute Guardian.Plug.current_claims(conn)

    assert Guardian.Plug.current_token(conn, key: :secret) == ctx.token
    assert Guardian.Plug.current_claims(conn, key: :secret) == ctx.claims
  end

  test "with a token and mismatching claims", ctx do
    conn =
      :get
      |> conn("/")
      |> put_req_header("authorization", ctx.token)
      |> VerifyHeader.call(module: ctx.impl, error_handler: ctx.handler, claims: %{no: "way"})

    assert conn.status == 401
    assert conn.resp_body == inspect({:invalid_token, "no"})
  end

  test "with a token and matching claims", ctx do
    conn =
      :get
      |> conn("/")
      |> put_req_header("authorization", ctx.token)
      |> VerifyHeader.call(module: ctx.impl, error_handler: ctx.handler, claims: ctx.claims)

    refute conn.status == 401
    assert Guardian.Plug.current_token(conn) == ctx.token
    assert Guardian.Plug.current_claims(conn) == ctx.claims
  end

  test "with a token and no specified claims", ctx do
    conn =
      :get
      |> conn("/")
      |> put_req_header("authorization", ctx.token)
      |> VerifyHeader.call(module: ctx.impl, error_handler: ctx.handler)

    refute conn.status == 401
    assert Guardian.Plug.current_token(conn) == ctx.token
    assert Guardian.Plug.current_claims(conn) == ctx.claims
  end

  test "with an invalid token", ctx do
    conn =
      :get
      |> conn("/")
      |> put_req_header("authorization", "not a good one")
      |> VerifyHeader.call(module: ctx.impl, error_handler: ctx.handler)

    assert conn.status == 401
  end
end
