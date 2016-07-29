defmodule Guardian.Hooks do
  @moduledoc """
  This module helps to hook into the lifecycle of authentication.
  """
  use Behaviour

  defmacro __using__(_) do
    quote do
      @behaviour Guardian.Hooks

      def before_encode_and_sign(resource, type, claims) do
        {:ok, {resource, type, claims}}
      end
      def after_encode_and_sign(_, _, _, _), do: :ok
      def after_sign_in(conn, _), do: conn
      def before_sign_out(conn, _), do: conn
      def on_verify(claims, jwt), do: {:ok, {claims, jwt}}
      def on_revoke(claims, jwt), do: {:ok, {claims, jwt}}

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

  defcallback before_encode_and_sign(
    resource :: term,
    type :: atom,
    claims :: map()
  )

  defcallback after_encode_and_sign(
    resource :: term,
    type :: atom,
    claims :: map(),
    token :: String.t
  )

  defcallback after_sign_in(
    conn :: Plug.Conn.t,
    location :: atom | nil
  )

  defcallback before_sign_out(
    conn :: Plug.Conn.t,
    location :: atom | nil
  )

  defcallback on_verify(
    claims :: map(),
    jwt :: String.t
  )

  defcallback on_revoke(
    claims :: map(),
    jwt :: String.t
  )
end

defmodule Guardian.Hooks.Default do
  @moduledoc """
  Default implementation of GuardianHooks.
  """
  use Guardian.Hooks
end
