defmodule Guardian.Config do
  @moduledoc """
  Working with configuration for guardian.
  """

  @typedoc """
  Configuration values can be given using the following types:

  * `{:system, "FOO"}` - Read from the system environment
  * `{MyModule, :function_name}` - To call a function and use the result
  * `{MyModule, :func, [:some, :args]}` Calls the function on the module with args
  * `fn -> :some_value end` - an anonymous function whose result will be used
  * any other value
  """
  @type config_value :: {:system, String.t} |
                        {Module.t, atom} |
                        {Module.t, atom, list(any)} |
                        fun |
                        any

  @doc """
  Resolves possible values from a configuration.

  * `{:system, "FOO"}` - reads "FOO" from the environment
  * `{m, f}` - Calls function `f` on module `m` and returns the result
  * `{m, f, a}` - Calls function `f` on module `m` with arguments `a` and returns the result
  * `f` - Calls the function `f` and returns the result
  * value - Returns other values as is
  """
  @spec resolve_value(value :: config_value) :: any
  def resolve_value({:system, name}), do: System.get_env(name)
  def resolve_value({m, f}) when is_atom(m) and is_atom(f), do: apply(m, f, [])
  def resolve_value({m, f, a}) when is_atom(m) and is_atom(f), do: apply(m, f, a)
  def resolve_value(f) when is_function(f, 0), do: f.()
  def resolve_value(v), do: v
end
