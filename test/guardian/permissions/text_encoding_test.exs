defmodule Guardian.Permissions.TextEncodingTest do
  use ExUnit.Case, async: true

  defmodule Impl do
    use Guardian,
      permissions: %{
        user: [:read, :write],
        profile: %{read: 0b1, write: 0b10}
      }

    use Guardian.Permissions.Permissions, encoding: Guardian.Permissions.TextEncoding

    def subject_for_token(resource, _claims), do: {:ok, resource}
    def resource_from_claims(claims), do: {:ok, claims["sub"]}

    def build_claims(claims, _resource, opts) do
      encode_permissions_into_claims!(claims, Keyword.get(opts, :permissions))
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
      assert result == %{profile: ["write", "read"], user: ["read"]}
    end

    test "it encodes when provided with a string map" do
      perms = %{"profile" => ["read", "write"], "user" => ["read"]}
      result = Impl.encode_permissions!(perms)
      assert result == %{profile: ["write", "read"], user: ["read"]}
    end

    test "it encodes when provided with an integer" do
      perms = %{profile: [], user: 0b1}
      result = Impl.encode_permissions!(perms)
      assert result == %{profile: [], user: ["read"]}
    end

    test "it is ok with using max permissions" do
      perms = %{profile: Impl.max(), user: 0b1}
      result = Impl.encode_permissions!(perms)
      assert result == %{profile: ["read", "write"], user: ["read"]}
    end

    test "when setting from an integer it does not lose resolution" do
      perms = %{profile: Impl.max(), user: 0b111111}
      result = Impl.encode_permissions!(perms)
      assert result == %{profile: ["read", "write"], user: ["read", "write"]}
    end
  end

  describe "decode_permissions" do
    test "it decodes to an empty map when there are no permissions given" do
      perms = %{profile: ["read"], user: []}
      result = Impl.decode_permissions(perms)
      assert result == %{profile: [:read], user: []}
    end

    test "when setting from an integer it ignores extra resolution" do
      perms = %{profile: ["read", "write"], user: ["read", "write"]}
      result = Impl.decode_permissions(perms)
      assert result == %{profile: [:read, :write], user: [:read, :write]}
    end

    test "it ignores unknown permission sets" do
      perms = %{profile: ["read", "write"], unknown: ["read"]}
      result = Impl.decode_permissions(perms)
      assert result == %{profile: [:read, :write]}
    end
  end
end
