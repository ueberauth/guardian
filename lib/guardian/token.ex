defmodule Guardian.Token do
  @moduledoc """
  """
  @type jwt :: String.t
  @type secret_error :: {:error, :secret_not_found}
  @type signing_error :: {:error, :signing_error}
  @type encoding_error :: {:error, atom}
  @type dencoding_error :: {:error, atom}

  @callback peek_header(token :: jwt) :: map
  @callback peek_claims(token :: jwt) :: map
  @callback build_claims(
    sub :: String.t,
    token_type :: any,
    claims :: map,
    options :: Keyword.t
  ) :: {:ok, map} | {:error, atom}


  @callback sign_claims(claims :: map, options :: Keyword.t) :: {:ok, jwt} |
                                                                signing_error
  @callback decode_token(token :: jwt, secret :: secret) :: {:ok, jwt} |
                                                            decoding_error
end
