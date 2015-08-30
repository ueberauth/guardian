defmodule Guardian.Hooks do
  @moduledoc """
  This module helps to hook into the lifecycle of authentication.
  """
  use Behaviour

  defmacro __using__(_) do
    quote do
      @behaviour Guardian.Hooks

      def before_mint(resource, type, claims), do: { :ok, { resource, type, claims } }
      def after_mint(_, _, _, _), do: :ok
      def after_sign_in(conn, _), do: conn
      def before_sign_out(conn, _), do: conn
      def on_verify(claims, jwt), do: { :ok, { claims, jwt } }
      def on_revoke(claims, jwt), do: { :ok, { claims, jwt } }

      defoverridable [
        {:before_mint, 3},
        {:after_mint, 4},
        {:after_sign_in, 2},
        {:before_sign_out, 2},
        {:on_verify, 2},
        {:on_revoke, 2}
      ]
    end
  end

  defcallback before_mint(resource :: term, type :: atom, claims :: Map)
  defcallback after_mint(resource :: term, type :: atom, claims :: Map, token :: String.t)
  defcallback after_sign_in(conn :: Plug.Conn.t, location :: atom | nil)
  defcallback before_sign_out(conn :: Plug.Conn.t, location :: atom | nil)
  defcallback on_verify(claims :: Map, jwt :: String.t)
  defcallback on_revoke(claims :: Map, jwt :: String.t)
end

defmodule Guardian.Hooks.Default do
  use Guardian.Hooks
end
