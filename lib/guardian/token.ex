defmodule Guardian.Token do
  @moduledoc """
  The behaviour module for all token modules.

  Token modules are responsible for all the heavy lifting
  in Guardian. 
  """
  @type token :: String.t
  @type claims :: map()
  @type resource :: any()

  @type secret_error :: {:error, :secret_not_found}
  @type signing_error :: {:error, :signing_error}
  @type encoding_error :: {:error, atom()}
  @type decoding_error :: {:error, atom()}

  @callback peek(token :: token) :: map()
  @callback token_id() :: String.t
  @callback build_claims(
    mod :: Module.t,
    resource :: any(),
    sub :: String.t,
    claims :: claims(),
    options :: Keyword.t
  ) :: {:ok, claims()} | {:error, atom()}

  @callback create_token(
    mod :: Module.t,
    claims :: claims(),
    options :: Guardian.options()
  ) :: {:ok, token} | signing_error | secret_error | encoding_error

  @callback decode_token(
    mod :: Module.t,
    token :: token(),
    options :: Guadian.options()
  ) :: {:ok, token} | secret_error | decoding_error

  @callback verify_claims(
    mod :: Module.t,
    claims :: claims(),
    options :: Guardian.options()
  ) :: {:ok, claims()} | {:error, any()}

  @callback revoke(
    mod :: Module.t,
    claims :: claims(),
    token :: token(),
    options :: Guardian.options()
  ) :: {:ok, claims() | {:error, any()}}

  @callback refresh(
    mod :: Module.t,
    old_token :: token(),
    options :: Guardian.options()
  ) :: {:ok, {token(), claims()}, {token(), claims()}} | {:error, any()}

  @callback exchange(
    mod :: Module.t,
    old_token :: token(),
    from_type :: String.t,
    to_type :: String.t,
    options :: Guardian.options()
  ) :: {:ok, {token(), claims()}, {token(), claims()}} | {:error, any()}
end
