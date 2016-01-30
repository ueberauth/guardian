defmodule Guardian.PermissionsTest do
  use ExUnit.Case, async: true
  alias Guardian.Permissions

  setup do
    {
      :ok,
      %{
        "pem" => %{
          "default" => 7,
          "other" => 15
        }
      }
    }
  end

  test "fetches available permissions" do
    expected_default = [:read, :write, :update, :delete]
    expected_other = [:other_read, :other_write, :other_update, :other_delete]
    assert Permissions.available(:default) == expected_default
    assert Permissions.available(:other) == expected_other
    assert Permissions.available(:not_there) == []
  end

  test "fetches the value of the default set of permissions" do
    assert Permissions.to_value([:read, :write, :update]) == 7
  end

  test "fetches the value of an explicit set of permissions" do
    perms = [:other_read, :other_write, :other_update]
    assert Permissions.to_value(perms, :other) == 7
  end

  test "fetches the value and ignores other values" do
    default_perms = [:read, :write, :update, :not_here]
    other_perms = [:other_read, :other_write, :other_update, :not_here]
    assert Permissions.to_value(default_perms) == 7
    assert Permissions.to_value(other_perms, :other) == 7
  end

  test "fetches the values from an integer" do
    assert Permissions.to_value(271) == 271
  end

  test "when using max permissions all permissions are available" do
    epxected_default = [:delete, :read, :update, :write]
    expected_other = [:other_delete, :other_read, :other_update, :other_write]

    found_default = Permissions.to_list(Permissions.max)
    found_other = Permissions.to_list(Permissions.max, :other)

    assert Enum.sort(found_default) == expected_default
    assert Enum.sort(found_other) == expected_other
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
    ex_default = [:read, :write, :update]
    ex_other = [:other_read, :other_write, :other_update]
    assert Enum.sort(Permissions.to_list(7)) == Enum.sort(ex_deafult)
    assert Enum.sort(Permissions.to_list(7, :other)) == Enum.sort(ex_other)
  end

  test "ignores other values when fetching a list" do
    expected = [:write, :update, :delete]
    assert Enum.sort(Permissions.to_list(270)) == Enum.sort(expected)
  end

  test "fetches a restricted list of only perms that the system knows about" do
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

    assert Permissions.all?(val, val)
    assert Permissions.all?(val, [:read, :write, :update])

    expected_val = Permissions.to_value([:read, :write, :update, :delete])

    refute Permissions.all?(val, expected_val)
    refute Permissions.all?(val, [:read, :write, :update, :delete])
  end

  test "all? is false if the permission is not set" do
    val = Permissions.to_value([:read, :write, :update], :new_permission)
    refute Permissions.all?(val, [:read, :write, :update], :new_permission)
  end

  test "any? is true if any values are present" do
    val = Permissions.to_value([:read, :write, :update])

    assert Permissions.any?(val, val)
    assert Permissions.any?(val, [:read, :write, :update])

    assert Permissions.any?(val, 1)
    assert Permissions.any?(val, [:read])

    refute Permissions.any?(val, 0)
    refute Permissions.any?(val, [:delete])
  end

  test "all? is true if all values are present with a non-default set" do
    val = Permissions.to_value(
      [:other_read, :other_write, :other_update],
      :other
    )

    assert Permissions.all?(val, val, :other)
    assert Permissions.all?(
      val,
      [:other_read, :other_write, :other_update],
      :other
    )

    expected_val = Permissions.to_value(
      [:other_read, :other_write, :other_update, :other_delete],
      :other
    )

    refute Permissions.all?(val, expected_val, :other)
    refute Permissions.all?(
      val,
      [:other_read, :other_write, :other_update, :other_delete],
      :other
    )
  end

  test "any? is true if any values are present with a non-default set" do
    val = Permissions.to_value(
      [:other_read, :other_write, :other_update],
      :other
    )

    assert Permissions.any?(val, val, :other)
    assert Permissions.any?(
      val,
      [:other_read, :other_write, :other_update],
      :other
    )

    assert Permissions.any?(val, 1, :other)
    assert Permissions.any?(val, [:other_read], :other)

    refute Permissions.any?(val, 0, :other)
    refute Permissions.any?(val, [:delete], :other)
  end

  test "integration with generating and decoding permissions" do
    { :ok, jwt, _ } = Guardian.encode_and_sign(
      "User:1",
      "token",
      %{perms: %{default: [:read, :write], other: [:other_read, :other_write]}}
    )

    { :ok, claims } = Guardian.decode_and_verify(jwt, %{})

    # Check all the permutations of string vs atoms
    default_val = Permissions.to_value([:read, :write])
    other_val = Permissions.to_value([:other_read, :other_write], :other)

    assert default_val == Permissions.from_claims(claims)
    assert other_val == Permissions.from_claims(claims, :other)

    assert default_val == Permissions.to_value([:read, :write], "default")
    assert other_val == Permissions.to_value(
      [:other_read, :other_write],
      "other"
    )

    assert default_val == Permissions.to_value(["read", "write"], "default")
    assert other_val == Permissions.to_value(
      ["other_read", "other_write"],
      "other"
    )

    assert default_val == Permissions.to_value(["read", "write"], :default)
    assert other_val == Permissions.to_value(
      ["other_read", "other_write"],
      :other
    )

    exp1 = Permissions.to_list(default_val)
    exp2 = Permissions.to_list(default_val, :default)
    exp3 = Permissions.to_list(default_val, "default")

    assert Enum.sort([:write, :read]) == Enum.sort(exp1)
    assert Enum.sort([:write, :read]) == Enum.sort(exp2)
    assert Enum.sort([:write, :read]) == Enum.sort(exp3)

    exp1 = Permissions.to_list([:read, :write], :default)
    exp2 = Permissions.to_list([:read, :write], "default")
    exp3 = Permissions.to_list(["read", "write"], :default)
    exp4 = Permissions.to_list(["read", "write"], "default")

    assert Enum.sort([:write, :read]) == Enum.sort(exp1)
    assert Enum.sort([:write, :read]) == Enum.sort(exp2)
    assert Enum.sort([:write, :read]) == Enum.sort(exp3)
    assert Enum.sort([:write, :read]) == Enum.sort(exp4)

    exp1 = Permissions.to_list(other_val, :other)
    exp2 = Permissions.to_list(other_val, "other")
    exp3 = Permissions.to_list([:other_read, :other_write], :other)
    exp4 = Permissions.to_list([:other_read, :other_write], "other")
    exp5 = Permissions.to_list(["other_read", "other_write"], "other")
    exp6 = Permissions.to_list(["other_read", "other_write"], :other)

    assert Enum.sort([:other_write, :other_read]) == Enum.sort(exp1)
    assert Enum.sort([:other_write, :other_read]) == Enum.sort(exp2)
    assert Enum.sort([:other_write, :other_read]) == Enum.sort(exp3)
    assert Enum.sort([:other_write, :other_read]) == Enum.sort(exp4)
    assert Enum.sort([:other_write, :other_read]) == Enum.sort(exp5)
    assert Enum.sort([:other_write, :other_read]) == Enum.sort(exp6)
  end
end
