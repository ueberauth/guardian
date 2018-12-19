defmodule Guardian.PlugTest do
  @moduledoc false

  import Guardian.Support.Utils, only: [gather_function_calls: 0]
  use Plug.Test

  use ExUnit.Case, async: true

  defmodule Impl do
    @moduledoc false

    use Guardian,
      otp_app: :guardian,
      token_module: Guardian.Support.TokenModule

    import Guardian.Support.Utils, only: [send_function_call: 1]

    def subject_for_token(%{id: id} = r, claims) do
      send_function_call({__MODULE__, :subject_for_token, [r, claims]})
      {:ok, id}
    end

    def subject_for_token(%{"id" => id} = r, claims) do
      send_function_call({__MODULE__, :subject_for_token, [r, claims]})
      {:ok, id}
    end

    def resource_from_claims(%{"sub" => id} = claims) do
      send_function_call({__MODULE__, :subject_for_token, [claims]})
      {:ok, %{id: id}}
    end

    def after_sign_in(conn, resource, token, claims, opts) do
      send_function_call({
        __MODULE__,
        :after_sign_in,
        [:conn, resource, token, claims, opts]
      })

      {:ok, conn}
    end

    def before_sign_out(conn, key, opts) do
      send_function_call({
        __MODULE__,
        :before_sign_out,
        [:conn, key, opts]
      })

      {:ok, conn}
    end

    def on_revoke(claims, token, opts) do
      send_function_call({
        __MODULE__,
        :on_revoke,
        [claims, token, opts]
      })

      {:ok, claims}
    end
  end

  setup do
    {:ok, %{impl: __MODULE__.Impl, conn: conn(:post, "/")}}
  end

  describe "getters and setters" do
    test "put_current_token", ctx do
      conn = Guardian.Plug.put_current_token(ctx.conn, "ToKen", [])
      assert conn.private[:guardian_default_token] == "ToKen"

      conn = Guardian.Plug.put_current_token(ctx.conn, "tOkEn", key: :bob)
      assert conn.private[:guardian_bob_token] == "tOkEn"
    end

    test "put_current_claims", ctx do
      conn = Guardian.Plug.put_current_claims(ctx.conn, %{my: "claims"}, [])
      assert conn.private[:guardian_default_claims] == %{my: "claims"}

      conn =
        Guardian.Plug.put_current_claims(
          ctx.conn,
          %{bob: "claims"},
          key: :bob
        )

      assert conn.private[:guardian_bob_claims] == %{bob: "claims"}
    end

    test "put_current_resource", ctx do
      conn = Guardian.Plug.put_current_resource(ctx.conn, "resource", [])
      assert conn.private[:guardian_default_resource] == "resource"

      conn =
        Guardian.Plug.put_current_resource(
          ctx.conn,
          "resource2",
          key: :bob
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

  describe "sign_in without session" do
    @resource %{id: "bob"}

    test "it calls the right things", ctx do
      conn = ctx.conn
      assert %Plug.Conn{} = xconn = Guardian.Plug.sign_in(conn, ctx.impl, @resource, %{}, [])

      refute Guardian.Plug.session_active?(xconn)

      token = xconn.private[:guardian_default_token]
      claims = xconn.private[:guardian_default_claims]

      assert token
      assert claims
      assert xconn.private[:guardian_default_resource] == @resource

      expected = [
        {ctx.impl, :subject_for_token, [@resource, %{}]},
        {Guardian.Support.TokenModule, :build_claims, [ctx.impl, @resource, "bob", %{}, []]},
        {Guardian.Support.TokenModule, :create_token, [ctx.impl, claims, []]},
        {ctx.impl, :after_sign_in, [:conn, @resource, token, claims, []]}
      ]

      assert gather_function_calls() == expected
    end

    test "it stores the information in the correct location", ctx do
      conn = ctx.conn

      assert %Plug.Conn{} =
               xconn = Guardian.Plug.sign_in(conn, ctx.impl, @resource, %{}, key: :bob)

      refute Guardian.Plug.session_active?(conn)

      assert xconn.private[:guardian_bob_token]
      assert xconn.private[:guardian_bob_claims]
      assert xconn.private[:guardian_bob_resource] == @resource
    end
  end

  describe "sign_in with session" do
    @resource %{id: "bob"}

    setup %{conn: conn} do
      {:ok, %{conn: init_test_session(conn, %{})}}
    end

    test "it calls the right things", ctx do
      conn = ctx.conn
      assert %Plug.Conn{} = xconn = Guardian.Plug.sign_in(conn, ctx.impl, @resource, %{}, [])

      assert Guardian.Plug.session_active?(xconn)

      token = xconn.private[:guardian_default_token]
      claims = xconn.private[:guardian_default_claims]

      assert token
      assert claims
      assert xconn.private[:guardian_default_resource] == @resource

      assert get_session(xconn, :guardian_default_token) == xconn.private[:guardian_default_token]

      expected = [
        {ctx.impl, :subject_for_token, [@resource, %{}]},
        {Guardian.Support.TokenModule, :build_claims, [ctx.impl, @resource, "bob", %{}, []]},
        {Guardian.Support.TokenModule, :create_token, [ctx.impl, claims, []]},
        {ctx.impl, :after_sign_in, [:conn, @resource, token, claims, []]}
      ]

      assert gather_function_calls() == expected
    end
  end

  describe "put_session_token" do
    @resource %{id: "bob"}

    setup %{conn: conn} do
      {:ok, %{conn: init_test_session(conn, %{})}}
    end

    test "it puts the new token in the session", ctx do
      conn = ctx.conn
      new_conn = Guardian.Plug.put_session_token(conn, ctx.impl, "hai bob")
      assert get_session(new_conn, :guardian_default_token) == "hai bob"
    end
  end

  describe "sign_out with session" do
    @bob %{id: "bobby"}
    @jane %{id: "jane"}

    setup %{conn: conn} do
      conn = init_test_session(conn, %{})
      bob_claims = %{"sub" => "User:#{@bob.id}"}
      bob_token = Jason.encode!(%{claims: bob_claims}) |> Base.encode64()
      jane_claims = %{"sub" => "User:#{@jane.id}"}
      jane_token = Jason.encode!(%{claims: jane_claims}) |> Base.encode64()

      conn =
        conn
        |> put_session(:guardian_bob_token, bob_token)
        |> put_private(:guardian_bob_token, bob_token)
        |> put_private(:guardian_bob_claims, bob_claims)
        |> put_private(:guardian_bob_resource, @bob)
        |> put_session(:guardian_jane_token, jane_token)
        |> put_private(:guardian_jane_token, jane_token)
        |> put_private(:guardian_jane_claims, jane_claims)
        |> put_private(:guardian_jane_resource, @jane)

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
      %{conn: conn, bob: %{token: bob_token, claims: bob_claims}} = ctx

      assert %Plug.Conn{} = xconn = Guardian.Plug.sign_out(conn, ctx.impl, key: :bob)

      refute xconn.private[:guardian_bob_token]
      refute xconn.private[:guardian_bob_claims]
      refute xconn.private[:guardian_bob_resource]

      refute get_session(xconn, :guardian_bob_token)

      assert xconn.private[:guardian_jane_token]
      assert xconn.private[:guardian_jane_claims]
      assert xconn.private[:guardian_jane_resource]

      assert get_session(xconn, :guardian_jane_token)

      expected = [
        {ctx.impl, :before_sign_out, [:conn, :bob, [key: :bob]]},
        {Guardian.Support.TokenModule, :revoke, [ctx.impl, bob_claims, bob_token, [key: :bob]]},
        {ctx.impl, :on_revoke, [bob_claims, bob_token, [key: :bob]]}
      ]

      assert gather_function_calls() == expected
    end

    test "is removes all users", ctx do
      %{
        conn: conn,
        bob: %{token: bob_token, claims: bob_claims},
        jane: %{token: jane_token, claims: jane_claims}
      } = ctx

      assert %Plug.Conn{} = xconn = Guardian.Plug.sign_out(conn, ctx.impl, [])

      refute xconn.private[:guardian_bob_token]
      refute xconn.private[:guardian_bob_claims]
      refute xconn.private[:guardian_bob_resource]

      refute get_session(xconn, :guardian_bob_token)

      refute xconn.private[:guardian_jane_token]
      refute xconn.private[:guardian_jane_claims]
      refute xconn.private[:guardian_jane_resource]

      refute get_session(xconn, :guardian_jane_token)

      expected = [
        {ctx.impl, :before_sign_out, [:conn, :bob, []]},
        {Guardian.Support.TokenModule, :revoke, [ctx.impl, bob_claims, bob_token, []]},
        {ctx.impl, :on_revoke, [bob_claims, bob_token, []]},
        {ctx.impl, :before_sign_out, [:conn, :jane, []]},
        {Guardian.Support.TokenModule, :revoke, [ctx.impl, jane_claims, jane_token, []]},
        {ctx.impl, :on_revoke, [jane_claims, jane_token, []]}
      ]

      assert gather_function_calls() == expected
    end
  end

  describe "sign_out without session" do
    @bob %{id: "bobby"}
    @jane %{id: "jane"}

    setup %{conn: conn} do
      bob_claims = %{"sub" => "User:#{@bob.id}"}
      bob_token = Jason.encode!(%{claims: bob_claims}) |> Base.encode64()
      jane_claims = %{"sub" => "User:#{@jane.id}"}
      jane_token = Jason.encode!(%{claims: jane_claims}) |> Base.encode64()

      conn =
        conn
        |> put_private(:guardian_bob_token, bob_token)
        |> put_private(:guardian_bob_claims, bob_claims)
        |> put_private(:guardian_bob_resource, @bob)
        |> put_private(:guardian_jane_token, jane_token)
        |> put_private(:guardian_jane_claims, jane_claims)
        |> put_private(:guardian_jane_resource, @jane)

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
      %{conn: conn, bob: %{token: bob_token, claims: bob_claims}} = ctx

      assert %Plug.Conn{} = xconn = Guardian.Plug.sign_out(conn, ctx.impl, key: :bob)

      refute xconn.private[:guardian_bob_token]
      refute xconn.private[:guardian_bob_claims]
      refute xconn.private[:guardian_bob_resource]

      assert xconn.private[:guardian_jane_token]
      assert xconn.private[:guardian_jane_claims]
      assert xconn.private[:guardian_jane_resource]

      expected = [
        {Guardian.PlugTest.Impl, :before_sign_out, [:conn, :bob, [key: :bob]]},
        {Guardian.Support.TokenModule, :revoke,
         [Guardian.PlugTest.Impl, bob_claims, bob_token, [key: :bob]]},
        {Guardian.PlugTest.Impl, :on_revoke, [bob_claims, bob_token, [key: :bob]]}
      ]

      assert gather_function_calls() == expected
    end

    test "is removes all users", ctx do
      %{
        conn: conn,
        bob: %{token: bob_token, claims: bob_claims},
        jane: %{token: jane_token, claims: jane_claims}
      } = ctx

      assert %Plug.Conn{} = xconn = Guardian.Plug.sign_out(conn, ctx.impl, [])

      refute xconn.private[:guardian_bob_token]
      refute xconn.private[:guardian_bob_claims]
      refute xconn.private[:guardian_bob_resource]

      refute xconn.private[:guardian_jane_token]
      refute xconn.private[:guardian_jane_claims]
      refute xconn.private[:guardian_jane_resource]

      expected = [
        {Guardian.PlugTest.Impl, :before_sign_out, [:conn, :bob, []]},
        {Guardian.Support.TokenModule, :revoke,
         [Guardian.PlugTest.Impl, bob_claims, bob_token, []]},
        {Guardian.PlugTest.Impl, :on_revoke, [bob_claims, bob_token, []]},
        {Guardian.PlugTest.Impl, :before_sign_out, [:conn, :jane, []]},
        {Guardian.Support.TokenModule, :revoke,
         [Guardian.PlugTest.Impl, jane_claims, jane_token, []]},
        {Guardian.PlugTest.Impl, :on_revoke, [jane_claims, jane_token, []]}
      ]

      assert gather_function_calls() == expected
    end
  end

  describe "remember me token in cookie" do
    @resource %{id: "bobby"}

    test "it creates a cookie with the default token and key", ctx do
      conn = ctx.conn
      assert %Plug.Conn{} = xconn = Guardian.Plug.remember_me(conn, ctx.impl, @resource, %{}, [])

      assert Map.has_key?(xconn.resp_cookies, "guardian_default_token")
      %{value: token, max_age: max_age} = Map.get(xconn.resp_cookies, "guardian_default_token")

      # default max age
      assert max_age == 2_419_200
      assert token

      claims = %{"sub" => @resource.id, "typ" => "refresh"}
      ops = [token_type: "refresh"]

      expected = [
        {ctx.impl, :subject_for_token, [@resource, %{}]},
        {Guardian.Support.TokenModule, :build_claims, [ctx.impl, @resource, "bobby", %{}, ops]},
        {Guardian.Support.TokenModule, :create_token, [ctx.impl, claims, ops]}
      ]

      assert gather_function_calls() == expected
    end

    test "it creates a cookie with a default token and custom key", ctx do
      conn = ctx.conn

      assert %Plug.Conn{} =
               xconn = Guardian.Plug.remember_me(conn, ctx.impl, @resource, %{}, key: "test")

      assert Map.has_key?(xconn.resp_cookies, "guardian_test_token")
      %{value: token, max_age: max_age} = Map.get(xconn.resp_cookies, "guardian_test_token")

      # default max age
      assert max_age == 2_419_200
      assert token

      claims = %{"sub" => @resource.id, "typ" => "refresh"}
      ops = [token_type: "refresh", key: "test"]

      expected = [
        {ctx.impl, :subject_for_token, [@resource, %{}]},
        {Guardian.Support.TokenModule, :build_claims, [ctx.impl, @resource, "bobby", %{}, ops]},
        {Guardian.Support.TokenModule, :create_token, [ctx.impl, claims, ops]}
      ]

      assert gather_function_calls() == expected
    end

    test "it clears the cookie when calling clear remember me", ctx do
      conn = ctx.conn
      assert %Plug.Conn{} = xconn = Guardian.Plug.remember_me(conn, ctx.impl, @resource, %{}, [])

      assert Map.has_key?(xconn.resp_cookies, "guardian_default_token")
      assert %Plug.Conn{} = clear_conn = Guardian.Plug.clear_remember_me(xconn, [])
      res = Map.get(clear_conn.resp_cookies, "guardian_default_token")
      assert Map.get(res, :max_age, nil) == 0
      assert Map.get(res, :value, nil) == nil
    end

    test "it creates a cookie with the default token and key from an existing token", ctx do
      conn = ctx.conn
      claims = %{"sub" => @resource.id, "typ" => "refresh"}
      old_token = Jason.encode!(%{claims: claims}) |> Base.encode64()

      assert %Plug.Conn{} =
               xconn = Guardian.Plug.remember_me_from_token(conn, ctx.impl, old_token, claims)

      assert Map.has_key?(xconn.resp_cookies, "guardian_default_token")

      %{value: new_token, max_age: max_age} =
        Map.get(xconn.resp_cookies, "guardian_default_token")

      # default max age
      assert max_age == 2_419_200
      assert new_token

      expected = [
        # decode and verify the old token
        {Guardian.Support.TokenModule, :decode_token, [ctx.impl, old_token, []]},
        {Guardian.Support.TokenModule, :verify_claims, [ctx.impl, claims, []]},
        # as part of the exchange we decode and verify the old token again
        {Guardian.Support.TokenModule, :decode_token, [ctx.impl, old_token, []]},
        {Guardian.Support.TokenModule, :verify_claims, [ctx.impl, claims, []]},
        {Guardian.Support.TokenModule, :exchange,
         [ctx.impl, old_token, "refresh", "refresh", []]},
        # as part of the exchange we decode the old token to get the claims
        {Guardian.Support.TokenModule, :decode_token, [ctx.impl, old_token, []]}
      ]

      assert gather_function_calls() == expected
    end

    test "it clears the remember me token in sign out", ctx do
      conn = ctx.conn

      assert %Plug.Conn{} =
               remember_me_conn = Guardian.Plug.remember_me(conn, ctx.impl, @resource, %{})

      assert Map.has_key?(remember_me_conn.resp_cookies, "guardian_default_token")

      assert %Plug.Conn{} =
               signed_out_conn =
               Guardian.Plug.sign_out(remember_me_conn, ctx.impl, clear_remember_me: true)

      res = Map.get(signed_out_conn.resp_cookies, "guardian_default_token")
      assert Map.get(res, :value, nil) == nil
      assert Map.get(res, :max_age, nil) == 0
    end
  end

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

  defmodule PipelineImpl do
    use Guardian.Plug.Pipeline,
      otp_app: :guardian,
      module: __MODULE__.Impl,
      error_handler: __MODULE__.Handler
  end

  describe "after using a pipeline" do
    @resource %{id: "bob"}

    setup %{conn: conn} do
      conn =
        conn
        |> init_test_session(%{})
        |> __MODULE__.PipelineImpl.call(__MODULE__.PipelineImpl.init([]))

      {:ok, %{conn: conn}}
    end

    test "calls the right hooks", %{conn: conn} do
      conn =
        conn
        |> Impl.Plug.sign_in(@resource)

      %{guardian_default_token: token, guardian_default_claims: claims} = conn.private

      conn
      |> Impl.Plug.sign_out()

      expected = [
        {Guardian.PlugTest.Impl, :subject_for_token, [@resource, %{}]},
        {Guardian.Support.TokenModule, :build_claims,
         [Guardian.PlugTest.Impl, @resource, "bob", %{}, []]},
        {Guardian.Support.TokenModule, :create_token, [Guardian.PlugTest.Impl, claims, []]},
        {Guardian.PlugTest.Impl, :after_sign_in, [:conn, @resource, token, claims, []]},
        {Guardian.PlugTest.Impl, :before_sign_out, [:conn, :default, []]},
        {Guardian.Support.TokenModule, :revoke, [Guardian.PlugTest.Impl, claims, token, []]},
        {Guardian.PlugTest.Impl, :on_revoke, [claims, token, []]}
      ]

      assert gather_function_calls() == expected
    end
  end

  describe "#keys" do
    alias Guardian.Plug.Keys

    test "key_from_other/1 only calculates key from conn-keys" do
      assert Keys.key_from_other(:guardian_default_token) == :default
      assert Keys.key_from_other(:guardian_bob_claims) == :bob
      assert Keys.key_from_other(:guardian_jane_resource) == :jane
      assert Keys.key_from_other(:guardian_module) == nil
      assert Keys.key_from_other(:guardian_error_handler) == nil
      assert Keys.key_from_other(:plug_session) == nil
    end
  end
end
