defmodule Guardian.Jwt do
  alias Poison, as: JSON
  @behaviour Joken.Codec

  def encode(map), do: JSON.encode!(map)

  def decode(binary), do: JSON.decode!(binary, keys: :atoms!)
end
