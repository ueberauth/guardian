defmodule Guardian.Keys do
  def claims_key(key), do: String.to_atom("#{base_key(key)}_claims")
  def resource_key(key), do: String.to_atom("#{base_key(key)}_resource")
  def jwt_key(key), do: String.to_atom("#{base_key(key)}_jwt")

  def base_key(the_key = "guardian_" <> _), do: String.to_atom(the_key)
  def base_key(the_key), do: String.to_atom("guardian_#{the_key}")
end
