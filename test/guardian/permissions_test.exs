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
    assert Permissions.to_value(271) == 271
  end

  test "when using max permissions all permissions are available" do
    assert Enum.sort(Permissions.to_list(Permissions.max)) == [:delete, :read, :update, :write]
    assert Enum.sort(Permissions.to_list(Permissions.max, :other)) == [:other_delete, :other_read, :other_update, :other_write]
  end

  test "fetches the values from an integer with a type" do
    assert Permissions.to_value(271, :other) == 271
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

  test "all? is true if all values are present" do
    val = Permissions.to_value([:read, :write, :update])

    assert Permissions.all?(val, val) == true
    assert Permissions.all?(val, [:read, :write, :update]) == true

    expected_val = Permissions.to_value([:read, :write, :update, :delete])

    assert Permissions.all?(val, expected_val) == false
    assert Permissions.all?(val, [:read, :write, :update, :delete]) == false
  end

  test "all? is false if the permission is not set" do
    val = Permissions.to_value([:read, :write, :update], :new_permission)
    assert(Permissions.all?(val, [:read, :write, :update], :new_permission) == false)
  end

  test "any? is true if any values are present" do
    val = Permissions.to_value([:read, :write, :update])

    assert Permissions.any?(val, val) == true
    assert Permissions.any?(val, [:read, :write, :update]) == true

    assert Permissions.any?(val, 1) == true
    assert Permissions.any?(val, [:read]) == true

    assert Permissions.any?(val, 0) == false
    assert Permissions.any?(val, [:delete]) == false
  end

  test "all? is true if all values are present with a non-default set" do
    val = Permissions.to_value([:other_read, :other_write, :other_update], :other)

    assert Permissions.all?(val, val, :other) == true
    assert Permissions.all?(val, [:other_read, :other_write, :other_update], :other) == true

    expected_val = Permissions.to_value([:other_read, :other_write, :other_update, :other_delete], :other)

    assert Permissions.all?(val, expected_val, :other) == false
    assert Permissions.all?(val, [:other_read, :other_write, :other_update, :other_delete], :other) == false
  end

  test "any? is true if any values are present with a non-default set" do
    val = Permissions.to_value([:other_read, :other_write, :other_update], :other)

    assert Permissions.any?(val, val, :other) == true
    assert Permissions.any?(val, [:other_read, :other_write, :other_update], :other) == true

    assert Permissions.any?(val, 1, :other) == true
    assert Permissions.any?(val, [:other_read], :other) == true

    assert Permissions.any?(val, 0, :other) == false
    assert Permissions.any?(val, [:delete], :other) == false
  end
end

