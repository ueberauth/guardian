defmodule Guardian.JWT do
  @moduledoc false
  alias Poison, as: JSON

  @behaviour Joken.Config

  @on_load { :load_required_atoms, 0 }

  def secret_key, do: Guardian.config(:secret_key)

  def algorithm, do: :HS256

  def claim(_, _), do: nil

  def validate_claim(:iss, payload) do
    verify_issuer = Guardian.config(:verify_issuer, false)
    if verify_issuer do
      if Dict.get(payload, :iss) == Guardian.config(:issuer), do: :ok, else: { :error, :invalid_issuer }
    else
      :ok
    end
  end

  def validate_claim(:nbf, payload) do
    case Dict.get(payload, :nbf) do
      nil -> :ok
      nbf -> if nbf > Guardian.Utils.timestamp, do: { :error, :token_not_yet_valid }, else: :ok
    end
  end

  def validate_claim(:iat, payload) do
    case Dict.get(payload, :iat) do
      nil -> :ok
      iat -> if iat > Guardian.Utils.timestamp, do: { :error, :token_not_yet_valid }, else: :ok
    end
  end

  def validate_claim(:exp, payload) do
    case Dict.get(payload, :exp) do
      nil -> :ok
      exp -> if Dict.get(payload, :exp) < Guardian.Utils.timestamp, do: { :error, :token_expired }, else: :ok
    end
  end

  def validate_claim(key, value), do: :ok

  @doc false
  def load_required_atoms do
    IO.puts("Loading required atoms #{inspect([:iat, :aud, :sub, :exp, :iss, :pems])}")
    :ok
  end

  @doc false
  def encode(map), do: JSON.encode!(map)

  @doc false
  def decode(binary), do: JSON.decode!(binary, keys: :atoms!)

end
