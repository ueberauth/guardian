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
end
