defmodule Guardian.Token.VerifyTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias Guardian.Token.Verify

  defmodule Config do
    def config(:allowed_drift, _default), do: 0
  end

  describe "time_within_drift?/2" do
    test "returns false for a non-numeric time" do
      refute Verify.time_within_drift?(Config, "tomorrow")
    end
  end

  describe "test verify_literal_claims/3" do
    test "claims_to_check are nil" do
      claims = %{aud: "api_audience"}
      assert {:ok, ^claims} = Verify.verify_literal_claims(claims, nil, [])
    end

    test "token's claim value is a list" do
      to_check = %{aud: "api_audience1"}
      invalid_claims = %{aud: ["invalid_audience"]}
      valid_claims = %{aud: ["api_audience1", "another_irrelevant_audience"]}

      assert {:error, :aud} = Verify.verify_literal_claims(invalid_claims, to_check, [])
      assert {:ok, ^valid_claims} = Verify.verify_literal_claims(valid_claims, to_check, [])
    end

    test "both token's claim value and claims_to_check's value are lists" do
      to_check = %{aud: ["api_audience1", "api_audience2"]}
      invalid_claims = %{aud: ["api_audience1", "another_irrelevant_audience"]}
      valid_claims = %{aud: ["api_audience1", "api_audience2", "another_irrelevant_audience"]}

      assert {:error, :aud} = Verify.verify_literal_claims(invalid_claims, to_check, [])
      assert {:ok, ^valid_claims} = Verify.verify_literal_claims(valid_claims, to_check, [])
    end

    test "when claim's value isn't a list, it checks for equality" do
      to_check = %{aud: "api_audience1"}
      invalid_claims = %{aud: "another_invalid_audience"}
      valid_claims = %{aud: "api_audience1"}

      assert {:error, :aud} = Verify.verify_literal_claims(invalid_claims, to_check, [])
      assert {:ok, ^valid_claims} = Verify.verify_literal_claims(valid_claims, to_check, [])
    end

    test "token's claim didn't contain a claim" do
      to_check = %{aud: "api_audience1"}
      assert {:error, :aud} = Verify.verify_literal_claims(%{}, to_check, [])
    end
  end
end
