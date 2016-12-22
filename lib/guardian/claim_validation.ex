defmodule Guardian.ClaimValidation do
  @moduledoc """
  Validates claims found in a JWT.

  This provides the default implementation for Guardian and
  is used in Guardian.JWT

  To use it in your own module

      use Guardian.ClaimValidation
  """
  @callback validate_claim(String.t, map, map) :: :ok |
                                                        {:error, atom}

  defmacro __using__(_options \\ []) do
    quote do
      def validate_claim(:iss, payload, opts) do
        validate_claim("iss", payload, opts)
      end

      def validate_claim("iss", payload, _) do
        verify_issuer = Guardian.config(:verify_issuer, false)
        if verify_issuer do
          if Map.get(payload, "iss") == Guardian.config(:issuer) do
            :ok
          else
            {:error, :invalid_issuer}
          end
        else
          :ok
        end
      end

      def validate_claim(:nbf, payload, opts) do
        validate_claim("nbf", payload, opts)
      end

      def validate_claim("nbf", payload, _) do
        case Map.get(payload, "nbf") do
          nil -> :ok
          nbf ->
            if time_within_allowed_drift?(nbf) || nbf < Guardian.Utils.timestamp do
              :ok
            else
              {:error, :token_not_yet_valid}
            end
        end
      end

      def validate_claim(:iat, payload, opts) do
        validate_claim("iat", payload, opts)
      end

      def validate_claim("iat", payload, _) do
        case Map.get(payload, "iat") do
          nil -> :ok
          iat ->
            if time_within_allowed_drift?(iat) || iat < Guardian.Utils.timestamp do
              :ok
            else
              {:error, :token_not_yet_valid}
            end
        end
      end

      def validate_claim(:exp, payload, opts) do
        validate_claim("exp", payload, opts)
      end

      def validate_claim("exp", payload, _) do
        case Map.get(payload, "exp") do
          nil -> :ok
          _ ->
            exp = payload["exp"]
            if time_within_allowed_drift?(exp) || exp > Guardian.Utils.timestamp do
              :ok
            else
              {:error, :token_expired}
            end
        end
      end

      def validate_claim(:typ, payload, opts) do
        validate_claim("typ", payload, opts)
      end

      def validate_claim("typ", payload, opts) do
        has_typ_key? = Map.has_key?(opts, "typ")
        if has_typ_key? and opts["typ"] != payload["typ"] do
          {:error, :invalid_type}
        else
          :ok
        end
      end

      def validate_claim(:aud, payload, opts) do
        validate_claim("aud", payload, opts)
      end

      def validate_claim("aud", payload, opts) do
        has_aud_key? = Map.has_key?(opts, "aud")
        if has_aud_key? and opts["aud"] != payload["aud"] do
          {:error, :invalid_audience}
        else
          :ok
        end
      end

      def time_within_allowed_drift?(expected_time) when is_integer(expected_time) do
        allowed_drift = Guardian.config(:allowed_drift, 0) / 1000
        diff = abs(expected_time - Guardian.Utils.timestamp)
        diff <= allowed_drift
      end
      def time_within_allowed_drift?(_), do: true
    end
  end
end
