defmodule Guardian.Plug.VerifySessionTest do
  @moduledoc false

  import Plug.Test

  alias Guardian.Plug, as: GPlug
  alias GPlug.{VerifySession, Pipeline}

  use ExUnit.Case, async: true

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

    def resource_from_claims(%{"sub" => id}), do: {:ok, %{id: id}}
  end

  @resource %{id: "bobby"}

  setup do
    impl = __MODULE__.Impl
    handler = __MODULE__.Handler
    {:ok, token, claims} = __MODULE__.Impl.encode_and_sign(@resource)
    {:ok, %{claims: claims, conn: conn(:get, "/"), token: token, impl: impl, handler: handler}}
  end

  test "with no session" do
    conn = :get |> conn("/") |> VerifySession.call([])
    assert GPlug.current_token(conn, []) == nil
    assert GPlug.current_claims(conn, []) == nil
  end

  test "it uses the module from options", ctx do
    conn =
      :get
      |> conn("/")
      |> init_test_session(%{guardian_default_token: ctx.token})
      |> VerifySession.call(module: ctx.impl)

    assert GPlug.current_token(conn, []) == ctx.token
    assert GPlug.current_claims(conn, []) == ctx.claims
  end

  test "it finds the module from the pipeline", ctx do
    conn =
      :get
      |> conn("/")
      |> init_test_session(%{guardian_default_token: ctx.token})
      |> Pipeline.put_module(ctx.impl)
      |> VerifySession.call([])

    assert GPlug.current_token(conn, []) == ctx.token
    assert GPlug.current_claims(conn, []) == ctx.claims
  end

  test "with an existing token on the connection it leaves it intact", ctx do
    {:ok, token, claims} = apply(ctx.impl, :encode_and_sign, [%{id: "jane"}])

    conn =
      :get
      |> conn("/")
      |> init_test_session(%{guardian_default_token: ctx.token})
      |> GPlug.put_current_token(token)
      |> GPlug.put_current_claims(claims)
      |> VerifySession.call([])

    assert GPlug.current_token(conn) == token
    assert GPlug.current_claims(conn) == claims
  end

  test "with no token in the session" do
    conn =
      :get
      |> conn("/")
      |> init_test_session(%{some: "other value"})
      |> VerifySession.call([])

    refute GPlug.current_token(conn)
    refute GPlug.current_claims(conn)
  end

  test "with no module", ctx do
    assert_raise RuntimeError, "`module` not set in Guardian pipeline", fn ->
      :get
      |> conn("/")
      |> init_test_session(%{guardian_default_token: ctx.token})
      |> VerifySession.call([])
    end
  end

  test "with a key specified", ctx do
    conn =
      :get
      |> conn("/")
      |> init_test_session(%{guardian_secret_token: ctx.token})
      |> VerifySession.call(module: ctx.impl, key: :secret)

    refute GPlug.current_token(conn)
    refute GPlug.current_claims(conn)

    assert GPlug.current_token(conn, key: :secret) == ctx.token
    assert GPlug.current_claims(conn, key: :secret) == ctx.claims
  end

  test "with a token and mismatching claims", ctx do
    conn =
      :get
      |> conn("/")
      |> init_test_session(%{guardian_default_token: ctx.token})
      |> VerifySession.call(module: ctx.impl, error_handler: ctx.handler, claims: %{no: "way"})

    assert conn.status == 401
    assert conn.resp_body == inspect({:invalid_token, "no"})
  end

  test "with a token and matching claims", ctx do
    conn =
      :get
      |> conn("/")
      |> init_test_session(%{guardian_default_token: ctx.token})
      |> VerifySession.call(module: ctx.impl, error_handler: ctx.handler, claims: ctx.claims)

    refute conn.status == 401
    assert GPlug.current_token(conn) == ctx.token
    assert GPlug.current_claims(conn) == ctx.claims
  end

  test "with a token and no specified claims", ctx do
    conn =
      :get
      |> conn("/")
      |> init_test_session(%{guardian_default_token: ctx.token})
      |> VerifySession.call(module: ctx.impl, error_handler: ctx.handler)

    refute conn.status == 401
    assert GPlug.current_token(conn) == ctx.token
    assert GPlug.current_claims(conn) == ctx.claims
  end

  test "with an invalid token", ctx do
    conn =
      :get
      |> conn("/")
      |> init_test_session(%{guardian_default_token: "not a good one"})
      |> VerifySession.call(module: ctx.impl, error_handler: ctx.handler)

    assert conn.status == 401
  end

  test "with multiple calls to different locations", ctx do
    {:ok, token, claims} = apply(ctx.impl, :encode_and_sign, [%{id: "jane"}])

    conn =
      :get
      |> conn("/")
      |> init_test_session(%{guardian_default_token: ctx.token, guardian_admin_token: token})
      |> VerifySession.call(module: ctx.impl, error_handler: ctx.handler, key: :admin)
      |> VerifySession.call(module: ctx.impl, error_handler: ctx.handler)

    refute conn.status == 401

    assert GPlug.current_token(conn) == ctx.token
    assert GPlug.current_claims(conn) == ctx.claims

    assert GPlug.current_token(conn, key: :admin) == token
    assert GPlug.current_claims(conn, key: :admin) == claims
  end
end
