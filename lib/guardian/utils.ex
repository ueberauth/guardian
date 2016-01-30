defmodule Guardian.Utils do
  @moduledoc false
  @doc false
  def stringify_keys(nil), do: %{}
  def stringify_keys(map) do
    Enum.reduce(
      Map.keys(map), %{},
      fn(k,acc) ->
        Map.put(acc, to_string(k), map[k])
      end
    )
  end

  @doc false
  def timestamp do
    {mgsec, sec, _usec} = :os.timestamp
    mgsec * 1_000_000 + sec
  end
end
