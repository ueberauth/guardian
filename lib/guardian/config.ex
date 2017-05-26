defmodule Guardian.Config do
  @moduledoc """
  Working with configuration for guardian.
  """
  use Mix.Config
  alias Mix.Config, as: MixConfig

  @type config_value :: {:system, String.t()} |
                        {Module.t(), atom()} |
                        {Module.t(), atom(), list(any())} |
                        fun() |
                        any()

  @spec merge_config_options(
    mod :: Module.t(),
    options :: Keyword.t()
  ) :: :ok
  @doc """
  Merges configuration for a given module

  Arguments:

  * mod - The module to attach the configuration to
  * options - The configuration to merge.

  The only _required_ option is `:otp_app`.
  This will not be merged into the configuration but everything else will be.
  """
  def merge_config_options(mod, options) do
    otp_app = Keyword.get(options, :otp_app)
    if !otp_app do
      raise "otp_app not defined for #{to_string(mod)}"
    end

    mod_config = Application.get_env(otp_app, mod, [])

    new_configs = Keyword.drop(options, [:otp_app])

    if Enum.count(new_configs) > 0 do
      [{otp_app, [{mod, mod_config}]}]
      |> MixConfig.merge([{otp_app, [{mod, new_configs}]}])
      |> MixConfig.persist()
      :ok
    else
      :ok
    end
  end

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
