defmodule Guardian.Token.Verify do
  @moduledoc """
  Interface for verifying tokens.

  This is intended to be used primarily by token modules but allows for a
  custom verification module to be created if the one that ships with your
  TokenModule is not quite what you want.
  """

  @doc """
  Verify a single claim.

  You should also include a fallback for claims that you are not validating.

  ```elixir
  def verify_claim(_mod, _key, claims, _opts), do: {:ok, claims}
  ```

  """
  @callback verify_claim(
              mod :: module,
              claim_key :: String.t(),
              claims :: Guardian.Token.claims(),
              options :: Guardian.options()
            ) :: {:ok, Guardian.Token.claims()} | {:error, atom}

  defmacro __using__(_opts \\ []) do
    quote do
      def verify_claims(mod, claims, opts) do
        Enum.reduce(claims, {:ok, claims}, fn
          {k, v}, {:ok, claims} -> verify_claim(mod, k, claims, opts)
          _, {:error, reason} = err -> err
        end)
      end

      def verify_claim(_mod, _claim_key, claims, _opts), do: {:ok, claims}

      defoverridable verify_claim: 4
    end
  end

  @spec time_within_drift?(mod :: module, time :: pos_integer) :: true | false
  @doc """
  Checks that a time value is within the `allowed_drift` as
  configured for the provided module.

  Allowed drift is measured in seconds and represents the maximum amount of
  time a token may be expired for an still be considered valid.

  This is to deal with clock skew.
  """
  def time_within_drift?(mod, time) when is_integer(time) do
    allowed_drift = apply(mod, :config, [:allowed_drift, 0]) / 1000
    diff = abs(time - Guardian.timestamp())
    diff <= allowed_drift
  end

  def time_within_drift?(_, _), do: true

  @spec verify_literal_claims(
          claims :: Guardian.Token.claims(),
          claims_to_check :: Guardian.Token.claims() | nil,
          opts :: Guardian.options()
        ) :: {:ok, Guardian.Token.claims()} | {:error, any}
  @doc """
  For claims, check the values against the values found in
  `claims_to_check`. If there is a claim to check that does not pass
  verification, it fails.

  When the value of a claim is a list, it checks that all values of
  the same claim in `claims_to_check` are members of the list.
  """
  def verify_literal_claims(claims, nil, _opts), do: {:ok, claims}

  def verify_literal_claims(claims, claims_to_check, _opts) do
    errors =
      Enum.reduce(claims_to_check, [], fn {k, v}, acc ->
        case verify_literal_claim(claims, k, v) do
          {:ok, _} -> acc
          error -> [error | acc]
        end
      end)

    if Enum.empty?(errors) do
      {:ok, claims}
    else
      hd(errors)
    end
  end

  @spec verify_literal_claims(map(), binary(), [binary()] | binary()) ::
          {:ok, [binary()] | binary()} | {:error, binary()}
  defp verify_literal_claim(claims, key, value) do
    claim_value = Map.get(claims, key)

    if valid_claims?(claim_value, value) do
      {:ok, claim_value}
    else
      {:error, key}
    end
  end

  defp valid_claims?(claim_values, valid) when is_list(claim_values) and is_list(valid) do
    Enum.all?(valid, &(&1 in claim_values))
  end

  defp valid_claims?(claim_values, valid) when is_list(claim_values), do: valid in claim_values

  defp valid_claims?(claim_value, valid), do: claim_value == valid
end
