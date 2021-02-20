defmodule Guardian.Plug.Keys do
  @moduledoc """
  Calculates keys for use with plug.

  The keys relate to where in the session/connection
  the data that Guardian deals in will be stored.

  `token`, `claims`, `resource` are all keyed.
  `token`, `claims`, `resource` are all stored on the conn.
  `token` is stored in the session if a session is found.
  """

  @doc false
  @spec claims_key() :: atom
  @spec claims_key(String.t() | atom) :: atom
  def claims_key(key \\ :default), do: String.to_atom("#{base_key(key)}_claims")

  @doc false
  @spec resource_key() :: atom
  @spec resource_key(String.t() | atom) :: atom
  def resource_key(key \\ :default), do: String.to_atom("#{base_key(key)}_resource")

  @doc false
  @spec token_key() :: atom
  @spec token_key(String.t() | atom) :: atom
  def token_key(key \\ :default), do: String.to_atom("#{base_key(key)}_token")

  @doc false
  @spec base_key(String.t() | atom) :: atom
  def base_key("guardian_" <> _ = the_key), do: String.to_atom(the_key)
  def base_key(the_key), do: String.to_atom("guardian_#{the_key}")

  def key_from_other(other_key) when is_binary(other_key) do
    ~r/^guardian_(?<key>.+)_(token|resource|claims)$/
    |> Regex.named_captures(other_key)
    |> extract_key()
  end

  def key_from_other(atom) do
    atom
    |> to_string()
    |> key_from_other()
  end

  defp extract_key(%{"key" => key}), do: String.to_atom(key)
  defp extract_key(_), do: nil
end
