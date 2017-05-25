defmodule Guardian.PlugTest do
  @moduledoc false
  # require Plug.Test
  use ExUnit.CaseTemplate
  use Plug.Test

  @secret String.duplicate("abcdef0123456789", 8)
  @cookie_opts [
    store: :cookie,
    key: "foobar",
    encryption_salt: "encrypted cookie salt",
    signing_salt: "signing salt",
    log: false
  ]

  @signing_opts Plug.Session.init(Keyword.put(@cookie_opts, :encrypt, false))

  def sign_conn(conn, secret \\ @secret) do
    put_in(conn.secret_key_base, secret)
    |> Plug.Session.call(@signing_opts)
    |> fetch_session()
  end

  defmodule Impl do
    use Guardian, otp_app: :guardian,
                  token_module: Guardian.Support.TokenModule

    import Guardian.Support.Utils, only: [
      print_function_call: 1,
    ]

    def subject_for_token(%{id: id} = r, claims) do
      print_function_call({__MODULE__, :subject_for_token, [r, claims]})
      {:ok, id}
    end

    def subject_for_token(%{"id" => id} = r, claims) do
      print_function_call({__MODULE__, :subject_for_token, [r, claims]})
      {:ok, id}
    end

    def resource_from_claims(%{"sub" => id} = claims) do
      print_function_call({__MODULE__, :subject_for_token, [claims]})
      {:ok, %{id: id}}
    end

    def after_sign_in(conn, resource, token, claims, opts) do
      print_function_call({
        __MODULE__,
        :after_sign_in,
        [:conn, resource, token, claims, opts]
      })

      {:ok, conn}
    end

    def before_sign_out(conn, key, opts) do
      print_function_call({
        __MODULE__,
        :before_sign_out,
        [:conn, key, opts]
      })
      {:ok, conn}
    end
  end

  setup do
    {:ok, %{impl: __MODULE__.Impl, conn: conn(:post, "/")}}
  end
end

defmodule Guardian.PlugTest.GettersAndSetters do
  use Guardian.PlugTest, async: true

  test "set_current_token", ctx do
    conn = Guardian.Plug.set_current_token(ctx.conn, "ToKen", [])
    assert conn.private[:guardian_default_token] == "ToKen"

    conn = Guardian.Plug.set_current_token(ctx.conn, "tOkEn", key: :bob)
    assert conn.private[:guardian_bob_token] == "tOkEn"
  end

  test "set_current_claims", ctx do
    conn = Guardian.Plug.set_current_claims(ctx.conn, %{my: "claims"}, [])
    assert conn.private[:guardian_default_claims] == %{my: "claims"}

    conn = Guardian.Plug.set_current_claims(
      ctx.conn, %{bob: "claims"}, key: :bob
    )
    assert conn.private[:guardian_bob_claims] == %{bob: "claims"}
  end

  test "set_current_resource", ctx do
    conn = Guardian.Plug.set_current_resource(ctx.conn, "resource", [])
    assert conn.private[:guardian_default_resource] == "resource"

    conn = Guardian.Plug.set_current_resource(
      ctx.conn, "resource2", key: :bob
    )
    assert conn.private[:guardian_bob_resource] == "resource2"
  end

  test "current_token", ctx do
    assert Guardian.Plug.current_token(ctx.conn, []) == nil

    conn = Plug.Conn.put_private(ctx.conn, :guardian_default_token, "tOkEn")
    assert Guardian.Plug.current_token(conn, []) == "tOkEn"

    conn = Plug.Conn.put_private(ctx.conn, :guardian_bob_token, "token")
    assert Guardian.Plug.current_token(conn, key: :bob) == "token"
  end

  test "current_claims", ctx do
    assert Guardian.Plug.current_claims(ctx.conn, []) == nil

    conn = Plug.Conn.put_private(ctx.conn, :guardian_default_claims, %{a: "b"})
    assert Guardian.Plug.current_claims(conn, []) == %{a: "b"}

    conn = Plug.Conn.put_private(ctx.conn, :guardian_bob_token, %{c: "d"})
    assert Guardian.Plug.current_token(conn, key: :bob) == %{c: "d"}
  end

  test "current_resource", ctx do
    assert Guardian.Plug.current_resource(ctx.conn, []) == nil

    conn = Plug.Conn.put_private(ctx.conn, :guardian_default_resource, :r1)
    assert Guardian.Plug.current_resource(conn, []) == :r1

    conn = Plug.Conn.put_private(ctx.conn, :guardian_bob_resource, :r2)
    assert Guardian.Plug.current_resource(conn, key: :bob) == :r2
  end

  test "authenticated? is true when there is a token present", ctx do
    refute Guardian.Plug.authenticated?(ctx.conn, [])
    refute Guardian.Plug.authenticated?(ctx.conn, key: :bob)

    conn =
      ctx.conn
      |> Plug.Conn.put_private(:guardian_default_token, "a")
      |> Plug.Conn.put_private(:guardian_bob_token, "b")

    assert Guardian.Plug.authenticated?(conn, [])
    assert Guardian.Plug.authenticated?(conn, key: :bob)
  end
end

defmodule Guardian.PlugTest.SignIn do
  defmodule WithoutSession do
    use Guardian.PlugTest, async: true
    import ExUnit.CaptureIO
    import Guardian.Support.Utils, only: [filter_function_calls: 1]

    @resource %{id: "bob"}

    test "it calls the right things", ctx do
      conn = ctx.conn
      io = capture_io(fn ->
        {:ok, %Plug.Conn{} = xconn} = Guardian.Plug.sign_in(
          conn, ctx.impl, @resource, %{}, []
        )

        %Plug.Conn.Unfetched{} = xconn.req_cookies
        %{} = xconn.resp_cookies
        assert Enum.empty?(xconn.resp_cookies)

        assert xconn.private[:guardian_default_token]
        assert xconn.private[:guardian_default_claims]
        assert xconn.private[:guardian_default_resource] == @resource
      end)

      function_calls = filter_function_calls(io)

      expected = [
        "Guardian.PlugTest.Impl.subject_for_token(%{id: \"bob\"}, %{})",
        "Guardian.Support.TokenModule.build_claims(Guardian.PlugTest.Impl, %{id: \"bob\"}, \"bob\", %{}, [])",
        "Guardian.Support.TokenModule.create_token(Guardian.PlugTest.Impl, %{\"sub\" => \"bob\"}, [])",
        "Guardian.PlugTest.Impl.after_sign_in(:conn, %{id: \"bob\"}, \"{\\\"claims\\\":{\\\"sub\\\":\\\"bob\\\"}}\", %{\"sub\" => \"bob\"}, [])"
      ]

      assert expected == function_calls
    end

    test "it stores the information in the correct location", ctx do
      conn = ctx.conn
      capture_io(fn ->
        {:ok, %Plug.Conn{} = xconn} = Guardian.Plug.sign_in(
          conn, ctx.impl, @resource, %{}, [key: :bob]
        )

        %Plug.Conn.Unfetched{} = xconn.req_cookies
        %{} = xconn.resp_cookies
        assert Enum.empty?(xconn.resp_cookies)

        assert xconn.private[:guardian_bob_token]
        assert xconn.private[:guardian_bob_claims]
        assert xconn.private[:guardian_bob_resource] == @resource
      end)
    end
  end

  defmodule WithSession do
    use Guardian.PlugTest, async: true
    import ExUnit.CaptureIO
    import Guardian.Support.Utils, only: [filter_function_calls: 1]

    @resource %{id: "bob"}

    setup %{conn: conn} do
      {:ok, %{conn: Guardian.PlugTest.sign_conn(conn)}}
    end

    test "it calls the right things", ctx do
      conn = ctx.conn
      io = capture_io(fn ->
        {:ok, %Plug.Conn{} = xconn} = Guardian.Plug.sign_in(
          conn, ctx.impl, @resource, %{}, []
        )

        assert is_map(xconn.req_cookies)
        %{} = xconn.resp_cookies
        assert Enum.empty?(xconn.resp_cookies)

        assert xconn.private[:guardian_default_token]
        assert xconn.private[:guardian_default_claims]
        assert xconn.private[:guardian_default_resource] == @resource

        assert Plug.Conn.get_session(xconn, :guardian_default_token) ==
          xconn.private[:guardian_default_token]
      end)

      function_calls = filter_function_calls(io)

      expected = [
        "Guardian.PlugTest.Impl.subject_for_token(%{id: \"bob\"}, %{})",
        "Guardian.Support.TokenModule.build_claims(Guardian.PlugTest.Impl, %{id: \"bob\"}, \"bob\", %{}, [])",
        "Guardian.Support.TokenModule.create_token(Guardian.PlugTest.Impl, %{\"sub\" => \"bob\"}, [])",
        "Guardian.PlugTest.Impl.after_sign_in(:conn, %{id: \"bob\"}, \"{\\\"claims\\\":{\\\"sub\\\":\\\"bob\\\"}}\", %{\"sub\" => \"bob\"}, [])"
      ]

      assert expected == function_calls
    end
  end
end

defmodule Guardian.PlugTest.SignOut do
  defmodule WithSession do
    use Guardian.PlugTest, async: true
    use Plug.Test
    import ExUnit.CaptureIO
    import Guardian.Support.Utils, only: [filter_function_calls: 1]

    @bob %{id: "bobby"}
    @jane %{id: "jane"}

    setup %{conn: conn} do
      conn = Guardian.PlugTest.sign_conn(conn)
      bob_claims = %{"sub" => "User:#{@bob.id}"}
      bob_token = Poison.encode!(%{claims: bob_claims})
      jane_claims = %{"sub" => "User:#{@jane.id}"}
      jane_token = Poison.encode!(%{claims: jane_claims})

      conn =
        conn
        |> Plug.Conn.put_session(:guardian_bob_token, bob_token)
        |> Plug.Conn.put_private(:guardian_bob_token, bob_token)
        |> Plug.Conn.put_private(:guardian_bob_claims, bob_claims)
        |> Plug.Conn.put_private(:guardian_bob_resource, @bob)
        |> Plug.Conn.put_session(:guardian_jane_token, jane_token)
        |> Plug.Conn.put_private(:guardian_jane_token, jane_token)
        |> Plug.Conn.put_private(:guardian_jane_claims, jane_claims)
        |> Plug.Conn.put_private(:guardian_jane_resource, @jane)

      {
        :ok,
        %{
          conn: conn,
          bob: %{token: bob_token, claims: bob_claims},
          jane: %{token: jane_token, claims: jane_claims}
        }
      }
    end

    test "it calls the right things", ctx do
      conn = ctx.conn
      io = capture_io(fn ->
        {:ok, %Plug.Conn{} = xconn} = Guardian.Plug.sign_out(
          conn, ctx.impl, [key: :bob]
        )

        refute xconn.private[:guardian_bob_token]
        refute xconn.private[:guardian_bob_claims]
        refute xconn.private[:guardian_bob_resource]

        refute Plug.Conn.get_session(xconn, :guardian_bob_token)

        assert xconn.private[:guardian_jane_token]
        assert xconn.private[:guardian_jane_claims]
        assert xconn.private[:guardian_jane_resource]

        assert Plug.Conn.get_session(xconn, :guardian_jane_token)
      end)

      function_calls = filter_function_calls(io)

      expected = [
        "Guardian.PlugTest.Impl.before_sign_out(:conn, :bob, [key: :bob])"
      ]

      assert expected == function_calls
    end

    test "is removes all users", ctx do
      conn = ctx.conn
      io = capture_io(fn ->
        {:ok, %Plug.Conn{} = xconn} = Guardian.Plug.sign_out(
          conn, ctx.impl, []
        )

        refute xconn.private[:guardian_bob_token]
        refute xconn.private[:guardian_bob_claims]
        refute xconn.private[:guardian_bob_resource]

        refute Plug.Conn.get_session(xconn, :guardian_bob_token)

        refute xconn.private[:guardian_jane_token]
        refute xconn.private[:guardian_jane_claims]
        refute xconn.private[:guardian_jane_resource]

        refute Plug.Conn.get_session(xconn, :guardian_jane_token)
      end)

      function_calls = filter_function_calls(io)

      expected = [
        "Guardian.PlugTest.Impl.before_sign_out(:conn, :bob, [])",
        "Guardian.PlugTest.Impl.before_sign_out(:conn, :jane, [])"
      ]

      assert expected == function_calls
    end
  end

  defmodule WithoutSession do
    use Guardian.PlugTest, async: true
    import ExUnit.CaptureIO
    import Guardian.Support.Utils, only: [filter_function_calls: 1]

    @bob %{id: "bobby"}
    @jane %{id: "jane"}

    setup %{conn: conn} do
      bob_claims = %{"sub" => "User:#{@bob.id}"}
      bob_token = Poison.encode!(%{claims: bob_claims})
      jane_claims = %{"sub" => "User:#{@jane.id}"}
      jane_token = Poison.encode!(%{claims: jane_claims})

      conn =
        conn
        |> Plug.Conn.put_private(:guardian_bob_token, bob_token)
        |> Plug.Conn.put_private(:guardian_bob_claims, bob_claims)
        |> Plug.Conn.put_private(:guardian_bob_resource, @bob)
        |> Plug.Conn.put_private(:guardian_jane_token, jane_token)
        |> Plug.Conn.put_private(:guardian_jane_claims, jane_claims)
        |> Plug.Conn.put_private(:guardian_jane_resource, @jane)

      {
        :ok,
        %{
          conn: conn,
          bob: %{token: bob_token, claims: bob_claims},
          jane: %{token: jane_token, claims: jane_claims}
        }
      }
    end

    test "it calls the right things", ctx do
      conn = ctx.conn
      io = capture_io(fn ->
        {:ok, %Plug.Conn{} = xconn} = Guardian.Plug.sign_out(
          conn, ctx.impl, [key: :bob]
        )

        refute xconn.private[:guardian_bob_token]
        refute xconn.private[:guardian_bob_claims]
        refute xconn.private[:guardian_bob_resource]

        assert xconn.private[:guardian_jane_token]
        assert xconn.private[:guardian_jane_claims]
        assert xconn.private[:guardian_jane_resource]
      end)

      function_calls = filter_function_calls(io)

      expected = [
        "Guardian.PlugTest.Impl.before_sign_out(:conn, :bob, [key: :bob])"
      ]

      assert expected == function_calls
    end

    test "is removes all users", ctx do
      conn = ctx.conn
      io = capture_io(fn ->
        {:ok, %Plug.Conn{} = xconn} = Guardian.Plug.sign_out(
          conn, ctx.impl, []
        )

        refute xconn.private[:guardian_bob_token]
        refute xconn.private[:guardian_bob_claims]
        refute xconn.private[:guardian_bob_resource]

        refute xconn.private[:guardian_jane_token]
        refute xconn.private[:guardian_jane_claims]
        refute xconn.private[:guardian_jane_resource]
      end)

      function_calls = filter_function_calls(io)

      expected = [
        "Guardian.PlugTest.Impl.before_sign_out(:conn, :bob, [])",
        "Guardian.PlugTest.Impl.before_sign_out(:conn, :jane, [])"
      ]

      assert expected == function_calls
    end
  end
end
