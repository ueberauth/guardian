defmodule Guardian.Plug.Keys do
  @moduledoc false

  @doc false
  def claims_key(key \\ :default) do
    String.to_atom("#{base_key(key)}_claims")
  end

  @doc false
  def resource_key(key \\ :default) do
    String.to_atom("#{base_key(key)}_resource")
  end

  @doc false
  def token_key(key \\ :default) do
    String.to_atom("#{base_key(key)}_token")
  end

  @doc false
  def base_key("guardian_" <> _ = the_key) do
    String.to_atom(the_key)
  end

  @doc false
  def base_key(the_key) do
    String.to_atom("guardian_#{the_key}")
  end

  def key_from_other(other_key) do
    other_key
    |> to_string()
    |> String.replace(~r/(_(token|resource|claims))?$/, "")
    |> find_key_from_other()
  end

  defp find_key_from_other("guardian_" <> key), do: String.to_atom(key)
  defp find_key_from_other(_), do: nil
end
