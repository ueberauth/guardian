defmodule Guardian.ConfigTest do
  use ExUnit.Case, async: true

  defmodule Impl do
    use Guardian, otp_app: :guardian,
                  issuer: "FooApp",
                  system_foo: {:system, "FOO"},
                  mod_fun_foo: {__MODULE__, :foo},
                  mod_fun_args: {__MODULE__, :foo, [1]},
                  fun: fn -> "blah" end

    use Guardian.TestHelper

    def foo, do: "module function foo"
    def foo(args), do: "mod fun args #{inspect(args)}"
  end

  setup do
    Guardian.Config.merge_config_options(
      __MODULE__.Impl,
      otp_app: :guardian,
      issuer: "FooApp"
    )
    {:ok, %{}}
  end

  test "config with a value" do
    assert __MODULE__.Impl.config(:issuer) == "FooApp"
  end

  test "config with no value" do
    assert __MODULE__.Impl.config(:not_a_thing) == nil
  end

  test "config with a default value" do
    assert __MODULE__.Impl.config(:not_a_thing, :this_is_a_thing) ==
      :this_is_a_thing
  end

  test "config with a system value" do
    System.put_env("FOO", "")
    assert __MODULE__.Impl.config(:system_foo) == ""
    System.put_env("FOO", "foo")
    assert __MODULE__.Impl.config(:system_foo) == "foo"
  end

  test "config with a {mod, fun}" do
    assert __MODULE__.Impl.config(:mod_fun_foo) == "module function foo"
  end

  test "config with a {mod, fun, args}" do
    assert __MODULE__.Impl.config(:mod_fun_args) == "mod fun args 1"
  end

  test "config with a function" do
    assert __MODULE__.Impl.config(:fun) == "blah"
  end

  test "merges configs for a module" do
    assert __MODULE__.Impl.config(:issuer) == "FooApp"
    Guardian.Config.merge_config_options(
      __MODULE__.Impl,
      otp_app: :guardian,
      issuer: "Bob"
    )
    assert __MODULE__.Impl.config(:issuer) == "Bob"
  end
end
