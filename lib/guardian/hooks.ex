defmodule Guardian.Hooks do
  @moduledoc """
  This module helps to hook into the lifecycle of authentication.
  """

  defmacro __using__(_) do
    quote do
      @behaviour Guardian.Hooks

      def before_encode_and_sign(resource, type, claims) do
        {:ok, {resource, type, claims}}
      end
      def after_encode_and_sign(resource, type, claims, token), do: {:ok, {resource, type, claims, token}}
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

  @callback before_encode_and_sign(
    resource :: term,
    type :: atom,
    claims :: map()
  ) :: {:ok, {term, atom, map}} | {:error, any}

  @callback after_encode_and_sign(
    resource :: term,
    type :: atom,
    claims :: map(),
    token :: String.t
  ) :: {:ok, {term, atom, map, String.t}} | {:error, any}

  @callback after_sign_in(
    conn :: Plug.Conn.t,
    location :: atom | nil
  ) :: Plug.Conn.t

  @callback before_sign_out(
    conn :: Plug.Conn.t,
    location :: atom | nil
  ) :: Plug.Conn.t

  @callback on_verify(
    claims :: map(),
    jwt :: String.t
  ) :: {:ok, {map(), String.t}} | {:error, any}

  @callback on_revoke(
    claims :: map(),
    jwt :: String.t
  ) :: {:ok, {map(), String.t}} | {:error, any}
end

defmodule Guardian.Hooks.Default do
  @moduledoc """
  Default implementation of GuardianHooks.
  """
  use Guardian.Hooks
end
