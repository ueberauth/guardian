defmodule Guardian.MultihookTest do
  @moduledoc false
  use ExUnit.Case, async: true

  # require Guardian.Hooks

  defmodule HookTest do
    @moduledoc """
    This hook module sends notifications to the caller.
    """

    defmacro __using__(counter) do
      quote do
        @behaviour Guardian.Hooks

        def before_encode_and_sign(resource, type, claims) do
          send self(), String.to_atom("before_encode_and_sign_#{unquote(counter)}")
          {:ok, {resource, type, claims}}
        end

        def after_encode_and_sign(_, _, _, _) do
          send self(), String.to_atom("after_encode_and_sign_#{unquote(counter)}")
          :ok
        end

        def after_sign_in(conn, _) do
          send self(), String.to_atom("after_sign_in_#{unquote(counter)}")
          conn
        end

        def before_sign_out(conn, _) do
          send self(), String.to_atom("before_sign_out_#{unquote(counter)}")
          conn
        end

        def on_verify(claims, jwt) do
          send self(), String.to_atom("on_verify_#{unquote(counter)}")
          {:ok, {claims, jwt}}
        end

        def on_revoke(claims, jwt) do
          send self(), String.to_atom("on_revoke_#{unquote(counter)}")
          {:ok, {claims, jwt}}
        end

        defoverridable [
          {:before_encode_and_sign, 3},
          {:after_encode_and_sign, 4},
          {:after_sign_in, 2},
          {:before_sign_out, 2},
          {:on_verify, 2},
          {:on_revoke, 2}
        ]
      end
    end
  end

  defmodule HookTest1 do
    use HookTest, 1
  end

  defmodule HookTest2 do
    @behaviour Guardian.Hooks

    def before_encode_and_sign("error", _, _) do
      {:error, "before_encode_and_sign_2_error"}
    end

    def before_encode_and_sign(resource, type, claims) do
      send self(), :before_encode_and_sign_2
      {:ok, {resource, type, claims}}
    end

    def after_encode_and_sign("error", _, _, _) do
      {:error, "after_encode_and_sign_2_error"}
    end

    def after_encode_and_sign(_, _, _, _) do
      send self(), :after_encode_and_sign_2
      :ok
    end

    def after_sign_in("error" = conn, _) do
      conn
    end

    def after_sign_in(conn, _) do
      send self(), :after_sign_in_2
      conn
    end

    def before_sign_out("error" = conn, _) do
      conn
    end

    def before_sign_out(conn, _) do
      send self(), :before_sign_out_2
      conn
    end

    def on_verify("error", _) do
      {:error, "on_verify_2_error"}
    end

    def on_verify(claims, jwt) do
      send self(), :on_verify_2
      {:ok, {claims, jwt}}
    end

    def on_revoke("error", _) do
      {:error, "on_revoke_2_error"}
    end

    def on_revoke(claims, jwt) do
      send self(), :on_revoke_2
      {:ok, {claims, jwt}}
    end
  end

  defmodule HookTest3 do
    use HookTest, 3
  end

  setup do
    config = Application.get_env :guardian, Guardian

    multihook_config = [hooks: [HookTest1, HookTest2, HookTest3]] ++ config
    Application.put_env :guardian, Guardian, multihook_config

    on_exit fn ->
      Application.put_env :guardian, Guardian, config
    end
  end

  test "Guardian.hooks_module" do
    assert Guardian.hooks_module == Guardian.Multihook
  end

  test "Guardian.hooks_modules" do
    assert Guardian.hooks_modules == [HookTest1, HookTest2, HookTest3]
  end

  test "before_encode_and_sign" do
    {:ok, {1, 2, 3}} = Guardian.Multihook.before_encode_and_sign(1, 2, 3)
    assert_received :before_encode_and_sign_1
    assert_received :before_encode_and_sign_2
    assert_received :before_encode_and_sign_3
  end

  test "before_encode_and_sign with an error" do
    {:error, "before_encode_and_sign_2_error"} = Guardian.Multihook.before_encode_and_sign("error", 2, 3)

    assert_received :before_encode_and_sign_1
    refute_received :before_encode_and_sign_2
    refute_received :before_encode_and_sign_3
  end

  test "after_encode_and_sign" do
    :ok = Guardian.Multihook.after_encode_and_sign(1, 2, 3, 4)

    assert_received :after_encode_and_sign_1
    assert_received :after_encode_and_sign_2
    assert_received :after_encode_and_sign_3
  end

  test "after_encode_and_sign with an error" do
    {:error, "after_encode_and_sign_2_error"} = Guardian.Multihook.after_encode_and_sign("error", 2, 3, 4)

    assert_received :after_encode_and_sign_1
    refute_received :after_encode_and_sign_2
    refute_received :after_encode_and_sign_3
  end

  test "after_sign_in" do
    1 = Guardian.Multihook.after_sign_in(1, 2)

    assert_received :after_sign_in_1
    assert_received :after_sign_in_2
    assert_received :after_sign_in_3
  end

  test "after_sign_in with an error" do
    "error" = Guardian.Multihook.after_sign_in("error", 2)

    assert_received :after_sign_in_1
    refute_received :after_sign_in_2
    assert_received :after_sign_in_3
  end

  test "before_sign_out" do
    1 = Guardian.Multihook.before_sign_out(1, 2)

    assert_received :before_sign_out_1
    assert_received :before_sign_out_2
    assert_received :before_sign_out_3
  end

  test "before_sign_out with an error" do
    "error" = Guardian.Multihook.before_sign_out("error", 2)

    assert_received :before_sign_out_1
    refute_received :before_sign_out_2
    assert_received :before_sign_out_3
  end

  test "on_verify" do
    {:ok, {1, 2}} = Guardian.Multihook.on_verify(1, 2)
    assert_received :on_verify_1
    assert_received :on_verify_2
    assert_received :on_verify_3
  end

  test "on_verify with an error" do
    {:error, "on_verify_2_error"} = Guardian.Multihook.on_verify("error", 2)

    assert_received :on_verify_1
    refute_received :on_verify_2
    refute_received :on_verify_3
  end

  test "on_revoke" do
    {:ok, {1, 2}} = Guardian.Multihook.on_revoke(1, 2)
    assert_received :on_revoke_1
    assert_received :on_revoke_2
    assert_received :on_revoke_3
  end

  test "on_revoke with an error" do
    {:error, "on_revoke_2_error"} = Guardian.Multihook.on_revoke("error", 2)

    assert_received :on_revoke_1
    refute_received :on_revoke_2
    refute_received :on_revoke_3
  end
end
