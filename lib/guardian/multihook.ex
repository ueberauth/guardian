defmodule Guardian.Multihook do
  @moduledoc """
  Multihook implementation of GuardianHooks.
  """
  @behaviour Guardian.Hooks

  def before_encode_and_sign(resource, type, claims) do
    _before_encode_and_sign(Guardian.hooks_modules, {:ok, {resource, type, claims}})
  end

  defp _before_encode_and_sign(_, {:error, _reason} = results), do: results
  defp _before_encode_and_sign([], results), do: results
  defp _before_encode_and_sign([hook_module | hooks_modules], {:ok, {resource, type, claims}}) do
    _before_encode_and_sign(hooks_modules, hook_module.before_encode_and_sign(resource, type, claims))
  end

  def after_encode_and_sign(resource, type, claims, jwt) do
    _after_encode_and_sign(Guardian.hooks_modules, :ok, {resource, type, claims, jwt})
  end

  defp _after_encode_and_sign(_, {:error, _reason} = results, _), do: results
  defp _after_encode_and_sign([], :ok, _), do: :ok
  defp _after_encode_and_sign([hook_module | hooks_modules], :ok, {resource, type, claims, jwt}) do
    _after_encode_and_sign(hooks_modules, hook_module.after_encode_and_sign(resource, type, claims, jwt), {resource, type, claims, jwt})
  end

  def after_sign_in(conn, the_key) do
    Enum.reduce(Guardian.hooks_modules, conn, &(&1.after_sign_in(&2, the_key)))
  end

  def before_sign_out(conn, the_key) do
    Enum.reduce(Guardian.hooks_modules, conn, &(&1.before_sign_out(&2, the_key)))
  end

  def on_verify(claims, jwt) do
    _on_verify(Guardian.hooks_modules, {:ok, {claims, jwt}})
  end

  defp _on_verify(_, {:error, _reason} = results), do: results
  defp _on_verify([], results), do: results
  defp _on_verify([hook_module | hooks_modules], {:ok, {claims, jwt}}) do
    _on_verify(hooks_modules, hook_module.on_verify(claims, jwt))
  end

  def on_revoke(claims, jwt) do
    _on_revoke(Guardian.hooks_modules, {:ok, {claims, jwt}})
  end

  defp _on_revoke(_, {:error, _reason} = results), do: results
  defp _on_revoke([], results), do: results
  defp _on_revoke([hook_module | hooks_modules], {:ok, {claims, jwt}}) do
    _on_revoke(hooks_modules, hook_module.on_revoke(claims, jwt))
  end
end
