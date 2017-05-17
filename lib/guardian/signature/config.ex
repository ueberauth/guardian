defmodule Guardian.Signature.Config do
  @moduledoc """
  Configuration for verifying a signature
  """
  defstruct allowed_algos: ["HS512"], allowed_drift: 1_000, secret: nil
end
