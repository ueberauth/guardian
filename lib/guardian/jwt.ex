defmodule Guardian.Jwt do
  alias Poison, as: JSON
  @behaviour Joken.Codec

  @on_load { :load_required_atoms, 0 }

  def encode(map), do: JSON.encode!(map)

  def decode(binary) do
    JSON.decode!(binary, keys: :atoms!)
  end

  def load_required_atoms do
    IO.puts("Loading required atoms #{inspect([:iat, :aud, :sub, :exp, :iss, :s_csrf])}")
    :ok
  end
end
