defmodule Guardian.Utils do
  def stringify_keys(map) do
    Enum.reduce(Dict.keys(map), %{}, fn(k,acc) -> Dict.put(acc, to_string(k), map[k]) end)
  end

  def timestamp, do: Calendar.DateTime.now("Etc/UTC") |> Calendar.DateTime.Format.unix
end
