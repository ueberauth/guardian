defmodule Guardian.Serializer do
  @moduledoc """
  Guardian Serializer Behaviour.

  Guardian requires a serializer. This serializer is responsible for fetching
  the resource from the encoded value in the JWT and also encoding a resource
  into a String so that it may be stored in the JWT
  """

  @doc """
  Serializes the object into the token. Suggestion: \"User:2\"
  """
  @callback for_token(object :: term) :: {:ok, String.t} |
                                           {:error, String.t}

  @doc """
  De-serializes the object from a token
  """
  @callback from_token(subject :: String.t) :: {:ok, object :: term} |
                                                 {:error, String.t}
end
