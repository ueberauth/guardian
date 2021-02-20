defmodule Guardian.Permissions.BitwiseEncoding do
  @moduledoc """
  Bitwise encoding for permissions.
  """

  @behaviour Guardian.Permissions.PermissionEncoding
  use Bitwise

  def encode(value, _type, _perm_set) when is_integer(value) do
    value
  end

  def encode(value, type, perm_set) when is_list(value) do
    perms = Map.get(perm_set, type)
    Enum.reduce(value, 0, &encode_value(&1, perms, &2))
  end

  defp encode_value(value, perm_set, acc) do
    perm_set
    |> Map.get(to_string(value))
    |> bor(acc)
  end

  def decode(value, _type, _perm_set) when is_list(value) do
    value
    |> Enum.map(&to_string/1)
    |> Enum.map(&String.to_atom/1)
  end

  def decode(value, type, perm_set) when is_integer(value) do
    perms = Map.get(perm_set, type)

    for {k, v} <- perms, band(value, v) == v, into: [] do
      k |> to_string() |> String.to_atom()
    end
  end
end
