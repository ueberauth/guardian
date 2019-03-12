defmodule Guardian.Permissions.JsonEncoding do
  @behaviour Guardian.Permissions.PermissionEncoding
  use Bitwise

  def encode(value, type, perm_set) when is_integer(value) do
    perms = Map.get(perm_set, type)

    for {k, v} <- perms, band(value, v) == v, into: [] do
      k |> to_string() |> String.to_atom()
    end
  end

  def encode(value, type, perm_set) when is_list(value) do
    perms = Map.get(perm_set, type)
    Enum.reduce(value, [], &encode_value(&1, perms, &2))
  end

  defp encode_value(value, _perm_set, acc) when is_atom(value),
    do: [value | acc]

  defp encode_value(value, _perm_set, acc) when is_binary(value),
    do: [String.to_atom(value) | acc]

  def decode(value, _type, _perm_set) when is_list(value) do
    value |> Enum.map(&to_string/1) |> Enum.map(&String.to_atom/1)
  end
end
