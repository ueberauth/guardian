defmodule Guardian.ConfigTest do
  @moduledoc false
  use ExUnit.Case, async: true

  defmodule Impl do
    @moduledoc false
    use Guardian,
      otp_app: :guardian,
      issuer: "FooApp",
      mod_fun_args: {__MODULE__, :foo, [1]}

    use Guardian.TestHelper

    def foo, do: "module function foo"
    def foo(args), do: "mod fun args #{inspect(args)}"
  end

  test "config with a value" do
    assert Impl.config(:issuer) == "FooApp"
  end

  test "config with no value" do
    assert Impl.config(:not_a_thing) == nil
  end

  test "config with a default value" do
    assert Impl.config(:not_a_thing, :this_is_a_thing) == :this_is_a_thing
  end

  test "config with a {mod, fun, args}" do
    assert Impl.config(:mod_fun_args) == "mod fun args 1"
  end
end
