defmodule Guardian.JWT do
  @moduledoc false
  alias Poison, as: JSON
  @behaviour Joken.Codec

  @on_load { :load_required_atoms, 0 }

  @doc false
  def encode(map), do: JSON.encode!(map)

  @doc false
  def decode(binary) do
    JSON.decode!(binary, keys: :atoms!)
  end

  @doc false
  def load_required_atoms do
    IO.puts("Loading required atoms #{inspect([:iat, :aud, :sub, :exp, :iss, :s_csrf])}")
    :ok
  end
end
