defmodule Guardian.Keys do
  @moduledoc false

  @doc false
  def claims_key(key \\ :default), do: String.to_atom("#{base_key(key)}_claims")
  @doc false
  def resource_key(key \\ :default), do: String.to_atom("#{base_key(key)}_resource")
  @doc false
  def jwt_key(key \\ :default), do: String.to_atom("#{base_key(key)}_jwt")

  @doc false
  def base_key(the_key = "guardian_" <> _), do: String.to_atom(the_key)
  @doc false
  def base_key(the_key), do: String.to_atom("guardian_#{the_key}")

  def key_from_other(other_key) do
    String.replace(to_string(other_key), ~r/(_(jwt|resource|claims))?$/, "")
    |> find_key_from_other
  end

  defp find_key_from_other("guardian_" <> key), do: String.to_atom(key)
  defp find_key_from_other(_), do: nil
end
