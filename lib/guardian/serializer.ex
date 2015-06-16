defmodule Guardian.Serializer do
  use Behaviour

  @doc "Serializes the object into the token. Suggestion: \"User:2\""
  defcallback for_token(object :: term) :: String.t

  @doc "de-serializes the object from a token"
  defcallback from_token(subject :: String.t) :: { :ok, object :: term } | { :error, String.t }

  def fetch_user(claims) do
    case Dict.fetch(claims, :aud) do
      { :ok, aud } -> Guardian.serializer.from_token(aud)
      _ ->
        case Dict.fetch(claims, "aud") do
          { :ok, aud } -> Guardian.serializer.from_token(aud)
          _ -> { :error, "Not found" }
        end
    end
  end

  def fetch_user!(claims) do
    case fetch_user(claims) do
      { :ok, user } -> user
      { :error, reason } -> raise reason
    end
  end
end
