defmodule Guardian.Config do
  # ttl
  # serializer
  # verify_issuer
  defstruct issuer: nil

  def resolve_value({:system, name}), do: System.get_env(name)
  def resolve_value({m, f}) when is_atom(f), do: apply(m, f, [])
  def resolve_value({m, f, a}), do: apply(m, f, a)
  def resolve_value(f) when is_function(0), do: f.()
  def resolve_value(v), do: v
end
