defmodule Guardian.Token.OneTimeTest do
  use ExUnit.Case

  alias Guardian.Token.OneTime.Repo

  defmodule Impl do
    use Guardian.Token.OneTime,
      otp_app: :guardian,
      repo: Guardian.Token.OneTime.Repo,
      token_table: "one_time_tokens"

    def subject_for_token(%{id: id}, _), do: {:ok, to_string(id)}
    def resource_from_claims(%{"sub" => id}), do: {:ok, %{id: id}}
  end

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
  end

  test "it creates a token" do
    {:ok, token, full_claims} = Impl.encode_and_sign(%{id: "resource-id"}, %{claim: "one"})

    refute token == nil
    assert full_claims["claim"] == "one"
  end

  describe "with a valid token" do
    setup do
      claims = %{claim: "one"}
      id = "the-id"
      {:ok, token, _} = Impl.encode_and_sign(%{id: id}, claims)
      {:ok, %{claims: claims, id: id, token: token}}
    end

    test "the token can only be used once", ctx do
      {:ok, claims} = Impl.decode_and_verify(ctx.token)
      assert claims["claims"] == ctx.claims["claims"]

      assert Impl.resource_from_claims(claims) == {:ok, %{id: ctx.id}}

      assert Impl.decode_and_verify(ctx.token) == {:error, :token_not_found_or_expired}
    end
  end

  describe "revoking a token" do
    setup do
      {:ok, token, _} = Impl.encode_and_sign(%{id: "some id"})
      {:ok, %{token: token}}
    end

    test "cannot use the token once revoked", ctx do
      Impl.revoke(ctx.token)
      assert Impl.decode_and_verify(ctx.token) == {:error, :token_not_found_or_expired}
    end
  end

  describe "revoking a token that is no longer there" do
    setup do
      {:ok, token, _} = Impl.encode_and_sign(%{id: "some id"})
      {:ok, %{token: token}}
    end

    test "does not matter", ctx do
      Impl.revoke(ctx.token)
      assert Impl.decode_and_verify(ctx.token) == {:error, :token_not_found_or_expired}
      Impl.revoke(ctx.token)
      assert Impl.decode_and_verify(ctx.token) == {:error, :token_not_found_or_expired}
    end
  end

  test "it is not refreshable" do
    {:ok, token, _} = Impl.encode_and_sign(%{id: "some id"})
    assert Impl.refresh(token) == {:error, :not_refreshable}
  end

  test "it is not exchangable" do
    {:ok, token, _} = Impl.encode_and_sign(%{id: "some id"})
    assert Impl.exchange(token, "access", "blah") == {:error, :not_exchangeable}
  end
end
