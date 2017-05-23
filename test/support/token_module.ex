defmodule Guardian.Support.TokenModule do
  @moduledoc """
  A simple json encoding of tokens for testing purposes
  """
  @behaviour Guardian.Token

  import Guardian.Support.Utils, only: [print_function_call: 1]

  def token_id do
    print_function_call({__MODULE__, :token_id, []})
    UUID.uuid4()
  end

  def peek(token) do
    %{
      claims: Poison.decode!(token)["claims"]
    }
  end

  def build_claims(mod, resource, sub, claims, options) do
    args = [mod, resource, sub, claims, options]
    print_function_call({__MODULE__, :build_claims, args})

    claims =
      claims
      |> Map.put("sub", sub)

    if Keyword.get(options, :fail_build_claims) do
      {:error, Keyword.get(options, :fail_build_claims)}
    else
      {:ok, claims}
    end
  end

  def create_token(mod, claims, options) do
    print_function_call({__MODULE__, :create_token, [mod, claims, options]})

    if Keyword.get(options, :fail_create_token) do
      {:error, Keyword.get(options, :fail_create_token)}
    else
      {:ok, Poison.encode!(%{"claims" => claims})}
    end
  end

  def decode_token(mod, token, options) do
    print_function_call({__MODULE__, :decode_token, [mod, token, options]})

    if Keyword.get(options, :fail_decode_token) do
      {:error, Keyword.get(options, :fail_decode_token)}
    else
      {:ok, Poison.decode!(token)["claims"]}
    end
  end

  def verify_claims(mod, claims, options) do
    print_function_call({__MODULE__, :verify_claims, [mod, claims, options]})

    if Keyword.get(options, :fail_verify_claims) do
      {:error, Keyword.get(options, :fail_verify_claims)}
    else
      {:ok, claims}
    end
  end

  def revoke(mod, claims, token, options) do
    print_function_call({__MODULE__, :revoke, [mod, claims, token, options]})

    if Keyword.get(options, :fail_revoke) do
      {:error, Keyword.get(options, :fail_revoke)}
    else
      {:ok, claims}
    end
  end

  def refresh(mod, old_token, options) do
    print_function_call({
      __MODULE__,
      :refresh,
      [mod, old_token, options]
    })

    if Keyword.get(options, :fail_refresh) do
      {:error, Keyword.get(options, :fail_refresh)}
    else
      old_claims = Poison.decode!(old_token)["claims"]
      resp = {old_token, old_claims}
      {:ok, resp, resp}
    end
  end

  def exchange(mod, old_token, from_type, to_type, options) do
    print_function_call({
      __MODULE__,
      :exchange,
      [mod, old_token, from_type, to_type, options]
    })

    if Keyword.get(options, :fail_exchange) do
      {:error, Keyword.get(options, :fail_exchange)}
    else
      old_claims = Poison.decode!(old_token)["claims"]
      resp = {old_token, old_claims}
      {:ok, resp, resp}
    end
  end
end
