defmodule Guardian.Token.Verify do
  @moduledoc """
  Interface for verifying tokens.

  This is intended to be used primarily by token modules
  but allows for a custom verification module to be created
  if the one that ships with your TokenModule is not quite what you want.
  """

  @doc """
  Verify a single claim

  You should also include a fallback for claims that you are not validating

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
  configured for the provided module

  Allowed drift is measured in seconds and represents the maximum amount
  of time a token may be expired for an still be considered valid.
  This is to deal with clock skew.
  """
  def time_within_drift?(mod, time) when is_integer(time) do
    allowed_drift = apply(mod, :config, [:allowed_drift, 0]) / 1000
    diff = abs(time - Guardian.timestamp())
    diff <= allowed_drift
  end

  def time_within_drift?(_), do: true

  @spec verify_literal_claims(
          claims :: Guardian.Token.claims(),
          claims_to_check :: Guardian.Token.claims() | nil,
          opts :: Guardian.options()
        ) :: {:ok, Guardian.Token.claims()} | {:error, any}
  @doc """
  For claims, check the values against the values found in
  `claims_to_check`. If there is a claim to check that does not match
  verification fails.
  """
  def verify_literal_claims(claims, nil, _opts), do: {:ok, claims}

  def verify_literal_claims(claims, claims_to_check, _opts) do
    results = for {k, v} <- claims_to_check, into: [], do: verify_literal_claim(claims, k, v)

    errors = Enum.filter(results, &(elem(&1, 0) == :error))

    if Enum.any?(errors), do: hd(errors), else: {:ok, claims}
  end

  defp verify_literal_claim(claims, key, v) do
    if Map.get(claims, key) == v, do: {:ok, claims}, else: {:error, key}
  end
end
