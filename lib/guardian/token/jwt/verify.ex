defmodule Guardian.Token.Jwt.Verify do
  @moduledoc """
  Verifies standard jwt fields
  """
  use Guardian.Token.Verify
  alias Guardian.Token.{Verify}

  @doc false
  def verify_claim(mod, "iss", %{"iss" => iss} = claims, _opts) do
    issuer = apply(mod, :config, [:issuer])
    verify_issuer = apply(mod, :config, [:verify_issuer])
    if verify_issuer && issuer == iss do
      {:ok, claims}
    else
      {:error, :invalid_issuer}
    end
  end

  @doc false
  def verify_claim(mod, "nbf", %{"nbf" => nbf} = claims, _opts) do
    if nbf == nil do
      {:ok, claims}
    else
      if Verify.time_within_drift?(mod, nbf) ||
         nbf <= Guardian.timestamp()
      do
        {:ok, claims}
      else
        {:error, :token_not_yet_valid}
      end
    end
  end

  @doc false
  def verify_claim(mod, "exp", %{"exp" => exp} = claims, _opts) do
    if exp == nil do
      {:ok, claims}
    else
      if Verify.time_within_drift?(mod, exp) ||
         exp >= Guardian.timestamp()
      do
        {:ok, claims}
      else
        {:error, :token_expired}
      end
    end
  end

  @doc false
  def verify_claim(_mod, _claim_key, claims, _opts), do: {:ok, claims}
end
