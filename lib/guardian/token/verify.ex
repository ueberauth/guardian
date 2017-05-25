defmodule Guardian.Token.Verify do
  @moduledoc """
  Interface for verifying tokens
  """

  @callback verify_claim(
    mod :: Module.t,
    claim_key :: String.t,
    claims :: Guardian.Token.claims(),
    options :: Guardian.options()
  ) :: {:ok, Guardian.Token.claims()} | {:error, atom}

  defmacro __using__(_opts \\ []) do
    quote do
      def verify_claims(mod, claims, opts) do
        Enum.reduce(
          claims,
          {:ok, claims},
          fn {k, v}, {:ok, claims} -> verify_claim(mod, k, claims, opts)
             _, {:error, reason} = err -> err
          end
        )
      end

      def verify_claim(_mod, _claim_key, claims, _opts), do: {:ok, claims}

      defoverridable [verify_claim: 4]
    end
  end

  def time_within_drift?(mod, time) when is_integer(time) do
    allowed_drift = apply(mod, :config, [:allowed_drift, 0]) / 1000
    diff = abs(time - Guardian.timestamp())
    diff <= allowed_drift
  end
  def time_within_drift?(_), do: true

  def verify_literal_claims(claims, claims_to_check, _opts) do
    errors =
      for {k, v} <- claims_to_check,
        into: []
      do
        verify_literal_claim(claims, k, v)
      end
      |> Enum.filter(&(elem(&1, 0) == :error))

    if Enum.any?(errors) do
      hd(errors)
    else
      {:ok, claims}
    end
  end

  defp verify_literal_claim(claims, key, v) do
    if Map.get(claims, key) == v, do: {:ok, claims}, else: {:error, key}
  end
end
