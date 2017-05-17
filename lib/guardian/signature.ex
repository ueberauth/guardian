defmodule Guardian.Signature do
  @moduledoc """
  Verifies the signature of a signed token
  """

  alias Guardian.{Token, Signature.Config}

  @callback verify_signature(
    token :: Guardian.Token.jwt,
    config :: Config.t
  ) :: boolean
end
