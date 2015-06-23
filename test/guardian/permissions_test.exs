defmodule Guardian.PermissionsTest do
  use ExUnit.Case, async: true
  alias Guardian.Permissions

  setup do
    {
      :ok,
      %{
        pem: %{
          "default" => 7,
          "other" => 15
        }
      }
    }
  end

  test "fetches available permissions" do
    assert Permissions.available(:default) == [:read, :write, :update, :delete]
    assert Permissions.available(:other) == [:other_read, :other_write, :other_update, :other_delete]
    assert Permissions.available(:not_there) == []
  end

  test "fetches the value of the default set of permissions" do
    assert Permissions.to_value([:read, :write, :update]) == 7
  end

  test "fetches the value of an explicit set of permissions" do
    assert Permissions.to_value([:other_read, :other_write, :other_update], :other) == 7
  end

  test "fetches the value and ignores other values" do
    assert Permissions.to_value([:read, :write, :update, :not_here]) == 7
    assert Permissions.to_value([:other_read, :other_write, :other_update, :not_here], :other) == 7
  end

  test "fetches the values from an integer" do
    assert Permissions.to_value(271) == 15
  end

  test "handles an empty list when fetching values" do
    assert Permissions.to_value([]) == 0
  end

  test "handles string values" do
    assert Permissions.to_value(["read", "write", "update"]) == 7
  end

  test "fetches a list from a value" do
    assert Enum.sort(Permissions.to_list(7)) == Enum.sort([:read, :write, :update])
    assert Enum.sort(Permissions.to_list(7, :other)) == Enum.sort([:other_read, :other_write, :other_update])
  end

  test "ignores other values when fetching a list" do
    assert Enum.sort(Permissions.to_list(270)) == Enum.sort([:write, :update, :delete])
  end

  test "fetches a restricted list of only permissions that the system knows about" do
    assert Enum.sort(Permissions.to_list([:read, :other])) == [:read]
  end

  test "from_claims using the default", context do
    assert Permissions.from_claims(context) == 7
  end

  test "from_claims with an atom", context do
    assert Permissions.from_claims(context, :default) == 7
    assert Permissions.from_claims(context, :other) == 15
  end

  test "from_claims with a string", context do
    assert Permissions.from_claims(context, "default") == 7
    assert Permissions.from_claims(context, "other") == 15
  end

  test "from_claims with an unknown type", context do
    assert Permissions.from_claims(context, "not_there") == 0
  end
end

