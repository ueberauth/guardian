defmodule Guardian.Permissions.PermissionsTest do
  use ExUnit.Case, async: true

  import Plug.Test

  alias Guardian.Plug.Pipeline

  defmodule Impl do
    use Guardian,
      otp_app: :guardian,
      permissions: %{
        user: [:read, :write],
        profile: %{read: 0b1, write: 0b10}
      },
      token_module: Guardian.Support.TokenModule

    use Guardian.Permissions.Permissions, encoding: Guardian.Permissions.BitwiseEncoding

    def subject_for_token(resource, _claims), do: {:ok, resource}
    def resource_from_claims(claims), do: {:ok, claims["sub"]}

    def build_claims(claims, _resource, opts) do
      encode_permissions_into_claims!(claims, Keyword.get(opts, :permissions))
    end
  end

  defmodule Handler do
    @moduledoc false

    import Plug.Conn
    @behaviour Guardian.Plug.ErrorHandler

    @impl Guardian.Plug.ErrorHandler
    def auth_error(conn, {type, reason}, _opts) do
      body = inspect({type, reason})
      send_resp(conn, 403, body)
    end
  end

  describe "normalize_permissions" do
    test "it normalizes a list of permissions" do
      result =
        Guardian.Permissions.Permissions.normalize_permissions(%{
          some: [:read, :write],
          other: [:one, :two]
        })

      assert result == %{
               "some" => %{"read" => 0b1, "write" => 0b10},
               "other" => %{"one" => 0b1, "two" => 0b10}
             }
    end

    test "it normalizes a map of permissions" do
      perms = %{
        some: %{read: 0b1, write: 0b10},
        other: %{"one" => 0b1, "two" => 0b10}
      }

      result = Guardian.Permissions.Permissions.normalize_permissions(perms)

      assert result == %{
               "some" => %{"read" => 0b1, "write" => 0b10},
               "other" => %{"one" => 0b1, "two" => 0b10}
             }
    end

    test "it normalizes a mix" do
      perms = %{
        some: %{read: 0b1, write: 0b10},
        other: [:one, "two"]
      }

      result = Guardian.Permissions.Permissions.normalize_permissions(perms)

      assert result == %{
               "some" => %{"read" => 0b1, "write" => 0b10},
               "other" => %{"one" => 0b1, "two" => 0b10}
             }
    end
  end

  test "max is -1" do
    assert Impl.max() == -1
  end

  describe "any_permissions?" do
    test "it checks if any permissions matched" do
      assert Impl.any_permissions?(%{user: [:read, :write]}, %{user: [:read]})
    end

    test "it checks if permissions didn't match" do
      refute Impl.any_permissions?(%{user: [:write]}, %{user: [:read]})
    end
  end

  describe "all_permissions?" do
    test "it checks if all permissions matched" do
      assert Impl.all_permissions?(%{user: [:read, :write]}, %{user: [:read, :write]})
    end

    test "it checks if not all permissions matched" do
      refute Impl.all_permissions?(%{user: [:write]}, %{user: [:read, :write]})
    end
  end

  describe "available_permissions" do
    test "it provides all the permissions" do
      result = Impl.available_permissions()
      assert result == %{profile: [:read, :write], user: [:read, :write]}
    end
  end

  test "it raises on unknown permission set" do
    msg = "#{to_string(Impl)} - Type: not_a_thing"

    assert_raise Guardian.Permissions.Permissions.PermissionNotFoundError, msg, fn ->
      perms = %{not_a_thing: [:not_a_thing]}
      Impl.encode_permissions!(perms)
    end
  end

  test "it raises on unknown permissions" do
    assert_raise Guardian.Permissions.Permissions.PermissionNotFoundError, fn ->
      perms = %{profile: [:wot, :now, :brown, :cow]}
      Impl.encode_permissions!(perms)
    end
  end

  describe "when used as a plug" do
    setup do
      claims =
        %{"sub" => "user:1"}
        |> Impl.build_claims(nil, permissions: %{user: [:read, :write], profile: [:read]})

      conn =
        :get
        |> conn("/")
        |> Pipeline.call(module: Impl, error_handler: Handler)
        |> Guardian.Plug.put_current_claims(claims)

      {:ok, %{conn: conn, claims: claims}}
    end

    test "it does not allow when permissions are missing from ensure", ctx do
      opts =
        Guardian.Permissions.Permissions.init(
          ensure: %{user: [:write, :read], profile: [:read, :write]}
        )

      conn = Guardian.Permissions.Permissions.call(ctx.conn, opts)

      assert {403, _headers, body} = sent_resp(conn)
      assert body == "{:unauthorized, :unauthorized}"
      assert conn.halted
    end

    test "it does not allow when none of the one_of permissions match", ctx do
      opts =
        Guardian.Permissions.Permissions.init(
          one_of: [
            %{profile: [:write]},
            %{user: [:read], profile: [:write]}
          ]
        )

      conn = Guardian.Permissions.Permissions.call(ctx.conn, opts)

      assert {403, _headers, body} = sent_resp(conn)
      assert body == "{:unauthorized, :unauthorized}"
      assert conn.halted
    end

    test "it allows the request when permissions from ensure match", ctx do
      opts = Guardian.Permissions.Permissions.init(ensure: %{user: [:read], profile: [:read]})
      conn = Guardian.Permissions.Permissions.call(ctx.conn, opts)

      refute conn.halted

      opts = Guardian.Permissions.Permissions.init(ensure: %{user: [:read]})
      conn = Guardian.Permissions.Permissions.call(ctx.conn, opts)

      refute conn.halted
    end

    test "it allows when one of the one of permissions from one_of match", ctx do
      opts =
        Guardian.Permissions.Permissions.init(
          one_of: [
            %{user: [:write]},
            %{profile: [:write]},
            %{user: [:read]}
          ]
        )

      conn = Guardian.Permissions.Permissions.call(ctx.conn, opts)

      refute conn.halted

      opts =
        Guardian.Permissions.Permissions.init(
          one_of: [
            %{user: [:write]},
            %{profile: [:write]},
            %{profile: [:read]}
          ]
        )

      conn = Guardian.Permissions.Permissions.call(ctx.conn, opts)

      refute conn.halted
    end

    test "when there is no logged in resource it fails" do
      conn = :get |> conn("/") |> Pipeline.call(module: Impl, error_handler: Handler)

      opts = Guardian.Permissions.Permissions.init(ensure: %{user: [:read], profile: [:read]})
      conn = Guardian.Permissions.Permissions.call(conn, opts)

      assert conn.halted
      assert {403, _headers, body} = sent_resp(conn)
      assert body == "{:unauthorized, :missing_claims}"
    end

    test "when looking in a different location with correct permissions", ctx do
      opts =
        Guardian.Permissions.Permissions.init(
          ensure: %{user: [:read], profile: [:read]},
          key: :secret
        )

      conn =
        ctx.conn
        |> Guardian.Plug.put_current_claims(ctx.claims, key: :secret)
        |> Guardian.Permissions.Permissions.call(opts)

      refute conn.halted

      opts = Guardian.Permissions.Permissions.init(ensure: %{user: [:read]}, key: :secret)

      conn =
        ctx.conn
        |> Guardian.Plug.put_current_claims(ctx.claims, key: :secret)
        |> Guardian.Permissions.Permissions.call(opts)

      refute conn.halted
    end

    test "when looking in a different location with incorrect ensure permissions", ctx do
      opts =
        Guardian.Permissions.Permissions.init(
          ensure: %{user: [:read], profile: [:read]},
          key: :secret
        )

      conn = Guardian.Permissions.Permissions.call(ctx.conn, opts)

      assert conn.halted
      assert {403, _headers, body} = sent_resp(conn)
      assert body == "{:unauthorized, :unauthorized}"
    end

    test "when looking in a different location with incorrect one_of permissions", ctx do
      opts = Guardian.Permissions.Permissions.init(one_of: [%{user: [:read]}], key: :secret)
      conn = Guardian.Permissions.Permissions.call(ctx.conn, opts)

      assert conn.halted
      assert {403, _headers, body} = sent_resp(conn)
      assert body == "{:unauthorized, :unauthorized}"
    end

    test "with no permissions specified", ctx do
      opts = Guardian.Permissions.Permissions.init([])
      conn = Guardian.Permissions.Permissions.call(ctx.conn, opts)
      refute conn.halted
    end
  end
end
