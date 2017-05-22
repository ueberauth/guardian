defmodule Guardian.Config do
  # TODO: Give this a better moduledoc

  @moduledoc """
  Working with configuration for guardian? This module can help.
  """
  use Mix.Config

  # TODO: docs
  def merge_config_options(mod, options) do
    otp_app = Keyword.get(options, :otp_app)
    if !otp_app do
      raise "otp_app not defined for #{to_string(mod)}"
    end

    mod_config = Application.get_env(otp_app, mod, [])

    new_configs = Keyword.drop(options, [:otp_app])

    if Enum.count(new_configs) do
      [{otp_app, [{mod, mod_config}]}]
      |> Mix.Config.merge([{otp_app, [{mod, new_configs}]}])
      |> Mix.Config.persist()
    else
      :ok
    end
  end

  def resolve_value({:system, name}), do: System.get_env(name)
  def resolve_value({m, f}) when is_atom(m) and is_atom(f), do: apply(m, f, [])
  def resolve_value({m, f, a}) when is_atom(m) and is_atom(f) do
    apply(m, f, a)
  end
  def resolve_value(f) when is_function(f, 0), do: f.()
  def resolve_value(v), do: v
end
