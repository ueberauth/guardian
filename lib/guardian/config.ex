defmodule Guardian.Config do
  @moduledoc """
  Working with configuration for guardian.
  """

  @typedoc """
  Configuration values can be given using the following types:

  * `{MyModule, :func, [:some, :args]}` Calls the function on the module with args
  * any other value
  """
  @type config_value :: {module, atom, list(any)} | any

  @doc """
  Resolves possible values from a configuration.

  * `{m, f, a}` - Calls function `f` on module `m` with arguments `a` and returns the result
  * value - Returns other values as is
  """
  @spec resolve_value(value :: config_value) :: any
  def resolve_value({m, f, a}) when is_atom(m) and is_atom(f), do: apply(m, f, a)
  def resolve_value(v), do: v
end
