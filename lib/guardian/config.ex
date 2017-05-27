defmodule Guardian.Config do
  @moduledoc """
  Working with configuration for guardian.
  """

  @type config_value :: {:system, String.t()} |
                        {Module.t(), atom()} |
                        {Module.t(), atom(), list(any())} |
                        fun() |
                        any()

  @spec resolve_value(value :: config_value()) :: any()
  @doc """
  Resolves possible values from a configuration.

  * `{:system, "FOO"}` - reads "FOO" from the environment
  * `{m, f}` - Calls function `f` on module `m` and returns the result
  * `{m, f, a}` - Calls function `f` on module `m` with arguments `a` and returns the result
  * `f` - Calls the function `f` and returns the result
  * value - Returns other values as is
  """
  def resolve_value({:system, name}), do: System.get_env(name)
  def resolve_value({m, f}) when is_atom(m) and is_atom(f), do: apply(m, f, [])
  def resolve_value({m, f, a}) when is_atom(m) and is_atom(f) do
    apply(m, f, a)
  end
  def resolve_value(f) when is_function(f, 0), do: f.()
  def resolve_value(v), do: v
end
