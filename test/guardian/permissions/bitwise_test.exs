defmodule Guardian.Permissions.BitwiseTest do
  use ExUnit.Case, async: true

  alias Guardian.Permissions.Bitwise, as: GBits

  defmodule Impl do
    use Guardian, otp_app: :guardian,
                  permissions: %{
                    user: [:read, :write],
                    profile: %{read: 0b1, write: 0b10}
                  },
                  token_module: Guardian.Support.TokenModule

    def subject_for_token(resource, _claims), do: {:ok, resource}
    def resource_from_claims(claims), do: {:ok, claims["sub"]}

    use Guardian.Permissions.Bitwise

  end


  test "max is -1" do
    assert Impl.max == -1
  end

  describe "normalize_permissions" do
    test "it normalizes a list of permissions" do
      result = GBits.normalize_permissions(%{some: [:read, :write], other: [:one, :two]})
      assert result == %{
        "some" => %{"read" => 0b1, "write" => 0b10},
        "other" => %{"one" => 0b1, "two" => 0b10},
      }
    end

    test "it normalizes a map of permissions" do
      perms = %{
        some: %{read: 0b1, write: 0b10},
        other: %{"one" => 0b1, "two" => 0b10},
      }

      result = GBits.normalize_permissions(perms)
      assert result == %{
        "some" => %{"read" => 0b1, "write" => 0b10},
        "other" => %{"one" => 0b1, "two" => 0b10},
      }
    end

    test "it normalizes a mix" do
      perms = %{
        some: %{read: 0b1, write: 0b10},
        other: [:one, "two"],
      }
      result = GBits.normalize_permissions(perms)
      assert result == %{
        "some" => %{"read" => 0b1, "write" => 0b10},
        "other" => %{"one" => 0b1, "two" => 0b10},
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
      perms = %{profile: Impl.max, user: 0b1}
      result = Impl.encode_permissions!(perms)
      assert result == %{profile: -1, user: 0b1}
    end

    test "when setting from an integer it does not lose resolution" do
      perms = %{profile: Impl.max, user: 0b111111}
      result = Impl.encode_permissions!(perms)
      assert result == %{profile: -1, user: 0b111111}
    end

    test "it raises on unknown permission set" do
      msg = "#{to_string Impl} - Type: not_a_thing"
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
end
