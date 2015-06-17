defmodule Guardian.TestGuardianSerializer do
  @behaviour Guardian.Serializer

  def for_token(aud), do: { :ok, to_string(aud) }

  def from_token(claims), do: { :ok, Dict.get(claims, :aud) }
end

ExUnit.start()
