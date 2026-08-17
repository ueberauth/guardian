defmodule Guardian.Plug.VerifyHeaderTest do
  @moduledoc false

  import Plug.Test
  import Plug.Conn
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias Guardian.Plug.Pipeline
  alias Guardian.Plug.VerifyHeader

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

  test "with :realm option shows a warning message" do
    has_warning_message =
      :stderr
      |> capture_io(fn -> VerifyHeader.init(realm: "Bearer") end)
      |> String.contains?("`:realm` option is deprecated; please rename `:realm` to `:scheme` option instead.")

    assert has_warning_message
  end

  test "getting the scheme config" do
    opts = VerifyHeader.init(scheme: "Bearer")
    assert opts[:scheme_reg] == "Bearer:? +(.*)$"

    opts = VerifyHeader.init(scheme: "Basic")
    assert opts[:scheme_reg] == "Basic:? +(.*)$"
  end

  test "correctly reading the token from the header", ctx do
    conn =
      :get
      |> conn("/")
      |> put_req_header("authorization", "Basic #{ctx.token}")
      |> VerifyHeader.call(
        Keyword.merge(VerifyHeader.init(scheme: "Basic"), module: ctx.impl, error_handler: ctx.handler)
      )

    refute conn.status == 401
    assert Guardian.Plug.current_token(conn) == ctx.token
  end

  test "ignoring token from header with non-matching scheme", ctx do
    conn =
      :get
      |> conn("/")
      |> put_req_header("authorization", "Bearer #{ctx.token}")
      |> VerifyHeader.call(
        Keyword.merge(VerifyHeader.init(scheme: "Basic"), module: ctx.impl, error_handler: ctx.handler)
      )

    refute Guardian.Plug.current_token(conn) == ctx.token
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
    assert conn.halted
  end

  test "does not halt conn when option is set to false", ctx do
    conn =
      :get
      |> conn("/")
      |> put_req_header("authorization", "not a good one")
      |> VerifyHeader.call(module: ctx.impl, error_handler: ctx.handler, halt: false)

    assert conn.status == 401
    refute conn.halted
  end

  describe "with refresh_from_cookie option" do
    defmodule ImplJwt do
      @moduledoc false

      use Guardian,
        otp_app: :guardian,
        token_module: Guardian.Token.Jwt,
        issuer: "MyApp",
        verify_issuer: true,
        secret_key: "foo-de-fafa",
        allowed_algos: ["HS512", "ES512"],
        ttl: {4, :weeks},
        secret_fetcher: Guardian.Support.TokenModule.SecretFetcher,
        token_ttl: %{
          "access" => {1, :day},
          "refresh" => {2, :weeks}
        },
        handler: __MODULE__.Handler

      def subject_for_token(%{id: id}, _claims), do: {:ok, "User:#{id}"}
      def resource_from_claims(%{"sub" => "User:" <> sub}), do: {:ok, %{id: sub}}

      def the_secret_yo, do: config(:secret_key)
      def the_secret_yo(val), do: val

      def verify_claims(claims, opts) do
        if Keyword.get(opts, :fail_owner_verify_claims) do
          {:error, Keyword.get(opts, :fail_owner_verify_claims)}
        else
          {:ok, claims}
        end
      end

      def build_claims(claims, _opts) do
        Map.put(claims, "from_owner", "here")
      end
    end

    setup do
      impl = __MODULE__.ImplJwt
      handler = __MODULE__.Handler
      {:ok, token, claims} = __MODULE__.ImplJwt.encode_and_sign(@resource)
      {:ok, %{claims: claims, conn: conn(:get, "/"), token: token, impl: impl, handler: handler}}
    end

    test "when session is valid", ctx do
      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", ctx.token)
        |> Pipeline.put_module(ctx.impl)
        |> Pipeline.put_error_handler(ctx.handler)
        |> VerifyHeader.call(refresh_from_cookie: [])

      assert Guardian.Plug.current_token(conn, []) == ctx.token
      assert Guardian.Plug.current_claims(conn, []) == ctx.claims
    end

    test "when session is expired", ctx do
      {:ok, expired_token, _} = apply(ctx.impl, :encode_and_sign, [%{id: "jane"}, %{}, [ttl: {0, :second}]])
      {:ok, refresh_token, _} = apply(ctx.impl, :encode_and_sign, [%{id: "jane"}, %{}, [token_type: "refresh"]])
      :timer.sleep(1000)
      assert {:error, :token_expired} = apply(ctx.impl, :decode_and_verify, [expired_token])

      conn =
        :get
        |> conn("/")
        |> put_req_cookie("guardian_default_token", refresh_token)
        |> put_req_header("authorization", expired_token)
        |> Pipeline.put_module(ctx.impl)
        |> Pipeline.put_error_handler(ctx.handler)
        |> VerifyHeader.call(refresh_from_cookie: [])

      refute conn.halted
      assert new_access_token = Guardian.Plug.current_token(conn)
      assert {:ok, _} = apply(ctx.impl, :decode_and_verify, [new_access_token])
      assert %{"sub" => "User:jane", "typ" => "access"} = Guardian.Plug.current_claims(conn)
    end

    test "when session is expired and refresh_from_cookie: true", ctx do
      {:ok, expired_token, _} = apply(ctx.impl, :encode_and_sign, [%{id: "jane"}, %{}, [ttl: {0, :second}]])
      {:ok, refresh_token, _} = apply(ctx.impl, :encode_and_sign, [%{id: "jane"}, %{}, [token_type: "refresh"]])
      :timer.sleep(1000)
      assert {:error, :token_expired} = apply(ctx.impl, :decode_and_verify, [expired_token])

      conn =
        :get
        |> conn("/")
        |> put_req_cookie("guardian_default_token", refresh_token)
        |> put_req_header("authorization", expired_token)
        |> Pipeline.put_module(ctx.impl)
        |> Pipeline.put_error_handler(ctx.handler)
        |> VerifyHeader.call(refresh_from_cookie: true)

      refute conn.halted
      assert new_access_token = Guardian.Plug.current_token(conn)
      assert {:ok, _} = apply(ctx.impl, :decode_and_verify, [new_access_token])
      assert %{"sub" => "User:jane", "typ" => "access"} = Guardian.Plug.current_claims(conn)
    end

    test "when session is invalid", ctx do
      {:ok, token, _} = apply(ctx.impl, :encode_and_sign, [%{id: "jane"}])
      invalid_token = "#{token}whatever"
      {:ok, refresh_token, _} = apply(ctx.impl, :encode_and_sign, [%{id: "jane"}, %{}, [token_type: "refresh"]])

      conn =
        :get
        |> conn("/")
        |> put_req_cookie("guardian_default_token", refresh_token)
        |> put_req_header("authorization", invalid_token)
        |> Pipeline.put_module(ctx.impl)
        |> Pipeline.put_error_handler(ctx.handler)
        |> VerifyHeader.call(refresh_from_cookie: [module: ctx.impl])

      refute conn.halted
      assert new_access_token = Guardian.Plug.current_token(conn)
      assert {:ok, _} = apply(ctx.impl, :decode_and_verify, [new_access_token])
      assert %{"sub" => "User:jane", "typ" => "access"} = Guardian.Plug.current_claims(conn)
    end

    test "when no header found", ctx do
      {:ok, refresh_token, _} = apply(ctx.impl, :encode_and_sign, [%{id: "jane"}, %{}, [token_type: "refresh"]])

      conn =
        :get
        |> conn("/")
        |> put_req_cookie("guardian_default_token", refresh_token)
        |> Pipeline.put_module(ctx.impl)
        |> Pipeline.put_error_handler(ctx.handler)
        |> VerifyHeader.call(refresh_from_cookie: [module: ctx.impl])

      refute conn.halted
      assert new_access_token = Guardian.Plug.current_token(conn)
      assert {:ok, _} = apply(ctx.impl, :decode_and_verify, [new_access_token])
      assert %{"sub" => "User:jane", "typ" => "access"} = Guardian.Plug.current_claims(conn)
    end
  end

  describe "with a runtime secret" do
    @configured_secret "configured-secret-key"
    @tenant_secret "tenant-secret-key"

    defmodule SecretImpl do
      @moduledoc false

      use Guardian,
        otp_app: :guardian,
        token_module: Guardian.Token.Jwt,
        secret_key: "configured-secret-key",
        allowed_algos: ["HS512"]

      def subject_for_token(%{id: id}, _claims), do: {:ok, id}
      def resource_from_claims(%{"sub" => id}), do: {:ok, %{id: id}}
    end

    def tenant_secret, do: @tenant_secret

    def counted_secret(conn) do
      send(self(), :secret_resolved)
      conn.assigns[:tenant_secret]
    end

    defp resolve_count(n \\ 0) do
      receive do
        :secret_resolved -> resolve_count(n + 1)
      after
        0 -> n
      end
    end

    setup do
      impl = __MODULE__.SecretImpl
      handler = __MODULE__.Handler

      {:ok, tenant_token, tenant_claims} =
        __MODULE__.SecretImpl.encode_and_sign(@resource, %{}, secret: @tenant_secret)

      {:ok, configured_token, _} = __MODULE__.SecretImpl.encode_and_sign(@resource)

      {:ok,
       %{
         impl: impl,
         handler: handler,
         tenant_token: tenant_token,
         tenant_claims: tenant_claims,
         configured_token: configured_token
       }}
    end

    defp call_with(ctx, token, opts) do
      :get
      |> conn("/")
      |> put_req_header("authorization", "Bearer #{token}")
      |> Pipeline.put_module(ctx.impl)
      |> Pipeline.put_error_handler(ctx.handler)
      |> VerifyHeader.call(VerifyHeader.init(opts))
    end

    test "the :secret option overrides the implementation module secret", ctx do
      conn = call_with(ctx, ctx.tenant_token, secret: @tenant_secret)

      refute conn.halted
      assert Guardian.Plug.current_token(conn, []) == ctx.tenant_token
      assert Guardian.Plug.current_claims(conn, []) == ctx.tenant_claims
    end

    test "the :secret option is resolved from an {m, f, a} tuple", ctx do
      conn = call_with(ctx, ctx.tenant_token, secret: {__MODULE__, :tenant_secret, []})

      refute conn.halted
      assert Guardian.Plug.current_claims(conn, []) == ctx.tenant_claims
    end

    test "without the :secret option the implementation module secret is used", ctx do
      conn = call_with(ctx, ctx.configured_token, [])

      refute conn.halted
      assert Guardian.Plug.current_token(conn, []) == ctx.configured_token
    end

    test "a token signed with another secret is rejected", ctx do
      conn = call_with(ctx, ctx.tenant_token, secret: @configured_secret)

      assert conn.status == 401
      assert Guardian.Plug.current_token(conn, []) == nil
    end

    test "a nil :secret fails closed instead of falling back to the module secret", ctx do
      conn = call_with(ctx, ctx.configured_token, secret: nil)

      assert conn.status == 401
      assert conn.resp_body == inspect({:invalid_token, :secret_not_found})
      assert Guardian.Plug.current_token(conn, []) == nil
    end

    test "the :secret option accepts a function of the connection", ctx do
      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", "Bearer #{ctx.tenant_token}")
        |> Plug.Conn.assign(:tenant_secret, @tenant_secret)
        |> Pipeline.put_module(ctx.impl)
        |> Pipeline.put_error_handler(ctx.handler)
        |> VerifyHeader.call(VerifyHeader.init(secret: & &1.assigns.tenant_secret))

      refute conn.halted
      assert Guardian.Plug.current_claims(conn, []) == ctx.tenant_claims
    end

    test "a connection aware :secret returning nil fails closed", ctx do
      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", "Bearer #{ctx.tenant_token}")
        |> Pipeline.put_module(ctx.impl)
        |> Pipeline.put_error_handler(ctx.handler)
        |> VerifyHeader.call(VerifyHeader.init(secret: & &1.assigns[:tenant_secret]))

      assert conn.status == 401
      assert conn.resp_body == inspect({:invalid_token, :secret_not_found})
    end

    test "a connection aware :secret is resolved once per request", ctx do
      :get
      |> conn("/")
      |> put_req_header("authorization", "Bearer #{ctx.tenant_token}")
      |> Plug.Conn.assign(:tenant_secret, @tenant_secret)
      |> Pipeline.put_module(ctx.impl)
      |> Pipeline.put_error_handler(ctx.handler)
      |> VerifyHeader.call(VerifyHeader.init(secret: &__MODULE__.counted_secret/1))

      assert resolve_count() == 1
    end

    test "a connection aware :secret is not resolved when no token is present", ctx do
      :get
      |> conn("/")
      |> Pipeline.put_module(ctx.impl)
      |> Pipeline.put_error_handler(ctx.handler)
      |> VerifyHeader.call(VerifyHeader.init(secret: &__MODULE__.counted_secret/1))

      assert resolve_count() == 0
    end

    test "a :secret on the plug is not inherited by :refresh_from_cookie", ctx do
      {:ok, refresh_token, _} =
        __MODULE__.SecretImpl.encode_and_sign(@resource, %{}, token_type: "refresh", secret: @tenant_secret)

      conn =
        :get
        |> conn("/")
        |> put_req_cookie("guardian_default_token", refresh_token)
        |> fetch_cookies()
        |> Plug.Conn.assign(:tenant_secret, @tenant_secret)
        |> Pipeline.put_module(ctx.impl)
        |> Pipeline.put_error_handler(ctx.handler)
        |> VerifyHeader.call(VerifyHeader.init(secret: &__MODULE__.counted_secret/1, refresh_from_cookie: []))

      assert conn.status == 401
      assert conn.resp_body == inspect({:invalid_token, :invalid_token})
      assert resolve_count() == 0
    end

    test "a :secret set on both the plug and :refresh_from_cookie is resolved for each", ctx do
      {:ok, refresh_token, _} =
        __MODULE__.SecretImpl.encode_and_sign(@resource, %{}, token_type: "refresh", secret: @tenant_secret)

      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", "Bearer #{ctx.configured_token}")
        |> put_req_cookie("guardian_default_token", refresh_token)
        |> fetch_cookies()
        |> Plug.Conn.assign(:tenant_secret, @tenant_secret)
        |> Pipeline.put_module(ctx.impl)
        |> Pipeline.put_error_handler(ctx.handler)
        |> VerifyHeader.call(
          VerifyHeader.init(
            secret: &__MODULE__.counted_secret/1,
            refresh_from_cookie: [secret: &__MODULE__.counted_secret/1]
          )
        )

      refute conn.halted
      assert Guardian.Plug.current_claims(conn, [])["typ"] == "access"
      assert resolve_count() == 2
    end

    test "a connection aware :secret survives a compiled plug pipeline", ctx do
      defmodule TenantPipeline do
        @moduledoc false
        use Plug.Builder

        plug(Guardian.Plug.VerifyHeader, secret: &__MODULE__.tenant_secret/1)

        def tenant_secret(conn), do: conn.assigns[:tenant_secret]
      end

      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", "Bearer #{ctx.tenant_token}")
        |> Plug.Conn.assign(:tenant_secret, @tenant_secret)
        |> Pipeline.put_module(ctx.impl)
        |> Pipeline.put_error_handler(ctx.handler)
        |> TenantPipeline.call(TenantPipeline.init([]))

      refute conn.halted
      assert Guardian.Plug.current_claims(conn, []) == ctx.tenant_claims
    end
  end
end
