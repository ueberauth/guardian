defmodule Guardian.Token do
  @moduledoc """
  The behaviour module for all token modules.

  Token modules are responsible for all the heavy lifting
  in Guardian.
  """
  @type token :: String.t()
  @type claims :: map
  @type resource :: any
  @type ttl ::
          {pos_integer, :second}
          | {pos_integer, :seconds}
          | {pos_integer, :minute}
          | {pos_integer, :minutes}
          | {pos_integer, :hour}
          | {pos_integer, :hours}
          | {pos_integer, :day}
          | {pos_integer, :days}
          | {pos_integer, :week}
          | {pos_integer, :weeks}

  @type secret_error :: {:error, :secret_not_found}
  @type signing_error :: {:error, :signing_error}
  @type encoding_error :: {:error, atom}
  @type decoding_error :: {:error, atom}

  @doc """
  Inspect the contents of the token without validation or signature checking.
  """
  @callback peek(module :: module, token :: token) :: map

  @doc """
  Generate a unique id for a token.
  """
  @callback token_id() :: String.t()

  @doc """
  Build the default claims for the token.
  """
  @callback build_claims(
              mod :: module,
              resource :: any,
              sub :: String.t(),
              claims :: claims,
              options :: Keyword.t()
            ) :: {:ok, claims} | {:error, atom}

  @doc """
  Create the token including serializing and signing.
  """
  @callback create_token(mod :: module, claims :: claims, options :: Guardian.options()) ::
              {:ok, token} | signing_error | secret_error | encoding_error

  @doc """
  Decode the token. Without verification of the claims within it.
  """
  @callback decode_token(mod :: module, token :: token, options :: Guardian.options()) ::
              {:ok, token} | secret_error | decoding_error

  @doc """
  Verify the claims of a token.
  """
  @callback verify_claims(mod :: module, claims :: claims, options :: Guardian.options()) ::
              {:ok, claims} | {:error, any}

  @doc """
  Revoke a token (if appropriate).
  """
  @callback revoke(mod :: module, claims :: claims, token :: token, options :: Guardian.options()) ::
              {:ok, claims} | {:error, any}

  @doc """
  Refresh a token.
  """
  @callback refresh(mod :: module, old_token :: token, options :: Guardian.options()) ::
              {:ok, {token, claims}, {token, claims}} | {:error, any}

  @doc """
  Exchange a token from one type to another.
  """
  @callback exchange(
              mod :: module,
              old_token :: token,
              from_type :: String.t() | [String.t(), ...],
              to_type :: String.t(),
              options :: Guardian.options()
            ) :: {:ok, {token, claims}, {token, claims}} | {:error, any}
end
