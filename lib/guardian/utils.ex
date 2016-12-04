defmodule Guardian.Utils do
  @moduledoc false
  @doc false
  def stringify_keys(nil), do: %{}
  def stringify_keys(map) do
    Enum.reduce_while(map, nil, fn
      {key, _}, nil when is_binary(key) -> {:cont, nil}
      _, _ -> {:halt, do_stringify_keys(map)}
    end) || map
  end

  defp do_stringify_keys(map) do
    Enum.reduce(map, Map.new, fn {key, value}, acc ->
      Map.put(acc, to_string(key), value)
    end)
  end

  @doc false
  def timestamp do
    {mgsec, sec, _usec} = :os.timestamp
    mgsec * 1_000_000 + sec
  end
end
