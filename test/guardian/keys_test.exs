defmodule Guardian.KeysTest do
  use ExUnit.Case, async: true

  test "base_key with atom" do
    assert Guardian.Keys.base_key(:foo) == :guardian_foo
  end

  test "base_key beginning with guardian_" do
    assert Guardian.Keys.base_key("guardian_foo") == :guardian_foo
  end

  test "claims key" do
    assert Guardian.Keys.claims_key(:foo) == :guardian_foo_claims
  end

  test "resource key" do
    assert Guardian.Keys.resource_key(:foo) == :guardian_foo_resource
  end

  test "jwt_key" do
    assert Guardian.Keys.jwt_key(:foo) == :guardian_foo_jwt
  end
end
