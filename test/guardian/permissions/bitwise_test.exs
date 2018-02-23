defmodule Guardian.Permissions.BitwiseTest do
  use ExUnit.Case, async: true

  import Plug.Test

  alias Guardian.Plug, as: GPlug
  alias GPlug.Pipeline
  alias Guardian.Permissions.Bitwise, as: GBits

  defmodule Impl do
    use Guardian,
      otp_app: :guardian,
      permissions: %{
        user: [:read, :write],
        profile: %{read: 0b1, write: 0b10}
      },
      token_module: Guardian.Support.TokenModule

    use Guardian.Permissions.Bitwise

    def subject_for_token(resource, _claims), do: {:ok, resource}
    def resource_from_claims(claims), do: {:ok, claims["sub"]}

    def build_claims(claims, _resource, opts) do
      encode_permissions_into_claims!(claims, Keyword.get(opts, :permissions))
    end
  end

  defmodule Handler do
    @moduledoc false

    import Plug.Conn

    def auth_error(conn, {type, reason}, _opts) do
      body = inspect({type, reason})
      send_resp(conn, 403, body)
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

  describe "normalize_permissions" do
    test "it normalizes a list of permissions" do
      result = GBits.normalize_permissions(%{some: [:read, :write], other: [:one, :two]})

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

      result = GBits.normalize_permissions(perms)

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

      result = GBits.normalize_permissions(perms)

      assert result == %{
               "some" => %{"read" => 0b1, "write" => 0b10},
               "other" => %{"one" => 0b1, "two" => 0b10}
             }
    end
  end

  describe "available_permissions" do
    test "it provides all the permissions" do
      result = Impl.available_permissions()
      assert result == %{profile: [:read, :write], user: [:read, :write]}
    end
  end

  describe "encode_permissions" do
    test "it encodes to an empty map when there are no permissions given" do
      %{} = result = Impl.encode_permissions!(%{})
      assert Enum.empty?(result)
    end

    test "it encodes when provided with an atom map" do
      perms = %{profile: [:read, :write], user: [:read]}
      result = Impl.encode_permissions!(perms)
      assert result == %{profile: 0b11, user: 0b1}
    end

    test "it encodes when provided with a string map" do
      perms = %{"profile" => ["read", "write"], "user" => ["read"]}
      result = Impl.encode_permissions!(perms)
      assert result == %{profile: 0b11, user: 0b1}
    end

    test "it encodes when provided with an integer" do
      perms = %{profile: [], user: 0b1}
      result = Impl.encode_permissions!(perms)
      assert result == %{profile: 0, user: 0b1}
    end

    test "it is ok with using max permissions" do
      perms = %{profile: Impl.max(), user: 0b1}
      result = Impl.encode_permissions!(perms)
      assert result == %{profile: -1, user: 0b1}
    end

    test "when setting from an integer it does not lose resolution" do
      perms = %{profile: Impl.max(), user: 0b111111}
      result = Impl.encode_permissions!(perms)
      assert result == %{profile: -1, user: 0b111111}
    end

    test "it raises on unknown permission set" do
      msg = "#{to_string(Impl)} - Type: not_a_thing"

      assert_raise GBits.PermissionNotFoundError, msg, fn ->
        perms = %{not_a_thing: [:not_a_thing]}
        Impl.encode_permissions!(perms)
      end
    end

    test "it raises on unknown permissions" do
      assert_raise GBits.PermissionNotFoundError, fn ->
        perms = %{profile: [:wot, :now, :brown, :cow]}
        Impl.encode_permissions!(perms)
      end
    end
  end

  describe "decode_permissions" do
    test "it decodes to an empty map when there are no permissions given" do
      perms = %{profile: 0b1, user: 0}
      result = Impl.decode_permissions(perms)
      assert result == %{profile: [:read], user: []}
    end

    test "it decodes when provided with an atom map" do
      perms = %{profile: [:read], user: 0}
      result = Impl.decode_permissions(perms)
      assert result == %{profile: [:read], user: []}

      perms = %{profile: ["read"], user: 0}
      result = Impl.decode_permissions(perms)
      assert result == %{profile: [:read], user: []}
    end

    test "it is ok with using max permissions" do
      perms = %{profile: ["read"], user: -1}
      result = Impl.decode_permissions(perms)
      assert result == %{profile: [:read], user: [:read, :write]}
    end

    test "when setting from an integer it ignores extra resolution" do
      perms = %{profile: 0b1111, user: -1}
      result = Impl.decode_permissions(perms)
      assert result == %{profile: [:read, :write], user: [:read, :write]}
    end

    test "it ignores unknown permission sets" do
      perms = %{profile: 0b11, unknown: -1}
      result = Impl.decode_permissions(perms)
      assert result == %{profile: [:read, :write]}
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
        |> GPlug.put_current_claims(claims)

      {:ok, %{conn: conn, claims: claims}}
    end

    test "it does not allow when permissions are missing from ensure", ctx do
      opts = GBits.init(ensure: %{user: [:write, :read], profile: [:read, :write]})
      conn = GBits.call(ctx.conn, opts)

      assert {403, _headers, body} = sent_resp(conn)
      assert body == "{:unauthorized, :unauthorized}"
      assert conn.halted
    end

    test "it does not allow when none of the one_of permissions match", ctx do
      opts =
        GBits.init(
          one_of: [
            %{profile: [:write]},
            %{user: [:read], profile: [:write]}
          ]
        )

      conn = GBits.call(ctx.conn, opts)

      assert {403, _headers, body} = sent_resp(conn)
      assert body == "{:unauthorized, :unauthorized}"
      assert conn.halted
    end

    test "it allows the request when permissions from ensure match", ctx do
      opts = GBits.init(ensure: %{user: [:read], profile: [:read]})
      conn = GBits.call(ctx.conn, opts)

      refute conn.halted

      opts = GBits.init(ensure: %{user: [:read]})
      conn = GBits.call(ctx.conn, opts)

      refute conn.halted
    end

    test "it allows when one of the one of permissions from one_of match", ctx do
      opts =
        GBits.init(
          one_of: [
            %{user: [:write]},
            %{profile: [:write]},
            %{user: [:read]}
          ]
        )

      conn = GBits.call(ctx.conn, opts)

      refute conn.halted

      opts =
        GBits.init(
          one_of: [
            %{user: [:write]},
            %{profile: [:write]},
            %{profile: [:read]}
          ]
        )

      conn = GBits.call(ctx.conn, opts)

      refute conn.halted
    end

    test "when there is no logged in resource it fails" do
      conn = :get |> conn("/") |> Pipeline.call(module: Impl, error_handler: Handler)

      opts = GBits.init(ensure: %{user: [:read], profile: [:read]})
      conn = GBits.call(conn, opts)

      assert conn.halted
      assert {403, _headers, body} = sent_resp(conn)
      assert body == "{:unauthorized, :unauthorized}"
    end

    test "when looking in a different location with correct permissions", ctx do
      opts = GBits.init(ensure: %{user: [:read], profile: [:read]}, key: :secret)

      conn =
        ctx.conn
        |> GPlug.put_current_claims(ctx.claims, key: :secret)
        |> GBits.call(opts)

      refute conn.halted

      opts = GBits.init(ensure: %{user: [:read]}, key: :secret)

      conn =
        ctx.conn
        |> GPlug.put_current_claims(ctx.claims, key: :secret)
        |> GBits.call(opts)

      refute conn.halted
    end

    test "when looking in a different location with incorrect ensure permissions", ctx do
      opts = GBits.init(ensure: %{user: [:read], profile: [:read]}, key: :secret)
      conn = GBits.call(ctx.conn, opts)

      assert conn.halted
      assert {403, _headers, body} = sent_resp(conn)
      assert body == "{:unauthorized, :unauthorized}"
    end

    test "when looking in a different location with incorrect one_of permissions", ctx do
      opts = GBits.init(one_of: [%{user: [:read]}], key: :secret)
      conn = GBits.call(ctx.conn, opts)

      assert conn.halted
      assert {403, _headers, body} = sent_resp(conn)
      assert body == "{:unauthorized, :unauthorized}"
    end

    test "with no permissions specified", ctx do
      opts = GBits.init([])
      conn = GBits.call(ctx.conn, opts)
      refute conn.halted
    end
  end
end
