defmodule Guardian.Token.Jwt.Verify do
  @moduledoc """
  Verifies standard jwt fields
  """
  use Guardian.Token.Verify

  def verify_claim(mod, "iss", %{"iss" => iss} = claims) do
    issuer = apply(mod, :config, [:issuer])
    if issuer == iss, do: {:ok, claims}, else: {:error, :invalid_issuer}
  end

  def verify_claim(mod, "nbf", %{"nbf" => nbf} = claims) do
    if nbf == nil do
      {:ok, claims}
    else
      if Guardian.Token.Verify.time_within_drift?(mod, nbf) ||
         nbf <= Guardian.timestamp()
      do
        {:ok, claims}
      else
        {:error, :token_not_yet_valid}
      end
    end
  end

  def verify_claim(mod, "exp", %{"exp" => exp} = claims) do
    if exp == nil do
      {:ok, claims}
    else
      if Guardian.Token.Verify.time_within_drift?(mod, exp) ||
         exp >= Guardian.timestamp()
      do
        {:ok, claims}
      else
        {:error, :token_expired}
      end
    end
  end

  def verify_claim(_mod, _claim_key, claims), do: {:ok, claims}
end
