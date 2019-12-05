defmodule Guardian.Token.Jwt.Verify do
  @moduledoc """
  Verifies standard jwt fields
  """
  use Guardian.Token.Verify

  alias Guardian.Token.Verify

  @behaviour Guardian.Token.Verify

  @impl Guardian.Token.Verify
  @spec verify_claim(
          mod :: module,
          claim_key :: String.t(),
          claims :: Guardian.Token.claims(),
          options :: Guardian.options()
        ) :: {:ok, Guardian.Token.claims()} | {:error, atom}
  def verify_claim(mod, "iss", %{"iss" => iss} = claims, _opts) do
    issuer = apply(mod, :config, [:issuer])
    verify_issuer = apply(mod, :config, [:verify_issuer])

    cond do
      verify_issuer && issuer == iss -> {:ok, claims}
      verify_issuer -> {:error, :invalid_issuer}
      true -> {:ok, claims}
    end
  end

  def verify_claim(_mod, "nbf", %{"nbf" => nil} = claims, _opts), do: {:ok, claims}

  def verify_claim(mod, "nbf", %{"nbf" => nbf} = claims, _opts) do
    if Verify.time_within_drift?(mod, nbf) || nbf <= Guardian.timestamp() do
      {:ok, claims}
    else
      {:error, :token_not_yet_valid}
    end
  end

  def verify_claim(_mod, "exp", %{"exp" => nil} = claims, _opts), do: {:ok, claims}

  def verify_claim(mod, "exp", %{"exp" => exp} = claims, _opts) do
    if Verify.time_within_drift?(mod, exp) || exp >= Guardian.timestamp() do
      {:ok, claims}
    else
      {:error, :token_expired}
    end
  end

  def verify_claim(_mod, "auth_time", %{"auth_time" => nil} = claims, _opts), do: {:ok, claims}

  def verify_claim(mod, "auth_time", %{"auth_time" => auth_time} = claims, opts) do
    max_age = opts[:max_age] || mod.config(:max_age)

    cond do
      max_age == nil -> {:ok, claims}
      Verify.time_within_drift?(mod, auth_time) -> {:ok, claims}
      Guardian.timestamp() <= auth_time + Guardian.ttl_to_seconds(max_age) -> {:ok, claims}
      true -> {:error, :token_expired}
    end
  end

  def verify_claim(_mod, _claim_key, claims, _opts), do: {:ok, claims}
end
