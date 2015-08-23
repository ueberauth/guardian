defmodule Guardian.Hooks do
  @moduledoc """
  This module helps to hook into the lifecycle of authentication.
  """
  use Behaviour

  def run_before_mint(resource, type, claims) do
    run_before_mint_hooks({ :ok, { resource, type, claims } }, Guardian.hooks_modules)
  end

  def run_after_mint(resource, type, claims, jwt) do
    Guardian.hooks_modules || []
    |> Enum.map(&(&1.after_mint(resource, type, claims, jwt)))
    |> List.last
  end

  def run_after_sign_in(conn, key) do
    Enum.reduce(Guardian.hooks_modules || [], conn, &(&1.after_sign_in(&2, key)))
  end

  def run_before_sign_out(conn, key) do
    Enum.reduce(Guardian.hooks_modules || [], conn, &(&1.before_sign_out(&2, key)))
  end

  defmacro __using__(_) do
    quote do
      @behaviour Guardian.Hooks

      def before_mint(resource, type, claims), do: { :ok, { resource, type, claims } }
      def after_mint(_, _, _, _), do: :ok
      def after_sign_in(conn, _), do: conn
      def before_sign_out(conn, _), do: conn

      defoverridable [
        {:before_mint, 3},
        {:after_mint, 4},
        {:after_sign_in, 2},
        {:before_sign_out, 2}
      ]
    end
  end

  defcallback before_mint(resource :: term, type :: atom, claims :: Map)
  defcallback after_mint(resource :: term, type :: atom, claims :: Map, token :: String.t)
  defcallback after_sign_in(conn :: Plug.Conn.t, location :: atom | nil)
  defcallback before_sign_out(conn :: Plug.Conn.t, location :: atom | nil)

  defp run_before_mint_hooks( { :ok, tuple = { resource, type, claims } }, [hook|tail]) do
    run_before_mint_hooks(hook.before_mint(resource, type, claims), tail)
  end

  defp run_before_mint_hooks(response, []), do: response
  defp run_before_mint_hooks(response, nil), do: response
  defp run_before_mint_hooks(response = { :error, reason }, _),  do: response
end

defmodule Guardian.Hooks.Default do
  use Guardian.Hooks
end
