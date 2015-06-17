defmodule Guardian.Claims do
  import Guardian.Utils

  def app_claims, do: %{ :iss => Guardian.issuer } |> iat |> ttl
  def app_claims(existing_claims) do
    Dict.merge(app_claims, Enum.into(existing_claims, %{}))
  end

  def aud(claims, nil), do: aud(claims, "token")
  def aud(claims, audience) when is_atom(audience), do: aud(claims, to_string(audience))
  def aud(claims, audience), do: Dict.put(claims, :aud, audience)

  def sub(claims, subject) when is_atom(subject), do: sub(claims, to_string(subject))
  def sub(claims, subject), do: Dict.put(claims, :sub, subject)

  def iat(claims), do: Dict.put(claims, :iat, timestamp)
  def iat(claims, ts), do: Dict.put(claims, :iat, ts)

  def ttl(claims = %{ ttl: requested_ttl }) do
    claims
    |> Dict.delete(:ttl)
    |> ttl(requested_ttl)
  end

  def ttl(claims), do: ttl(claims, Guardian.config(:ttl, { 1_000_000_000, :seconds }))

  def ttl(claims = %{iat: iat}, requested_ttl) do
    case { iat, requested_ttl } do
      { nil, _ } -> Dict.put_new(claims, timestamp + 1_000_000_000)
      { iat, { seconds, :seconds } } -> Dict.put(claims, :exp, iat + seconds)
      { iat, { seconds, :second } } -> Dict.put(claims, :exp, iat + seconds)
      { iat, { millis, :millis } } -> Dict.put(claims, :exp, iat + millis / 1000)
      { iat, { millis, :milli } } -> Dict.put(claims, :exp, iat + millis / 1000)
      { iat, { minutes, :minutes } } -> Dict.put(claims, :exp, iat + minutes * 60)
      { iat, { minutes, :minute } } -> Dict.put(claims, :exp, iat + minutes * 60)
      { iat, { hours, :hours } } -> Dict.put(claims, :exp, iat + hours * 60 * 60)
      { iat, { hours, :hour } } -> Dict.put(claims, :exp, iat + hours * 60 * 60)
      { iat, { days, :days } } -> Dict.put(claims, :exp, iat + days * 24 * 60 * 60)
      { iat, { days, :day } } -> Dict.put(claims, :exp, iat + days * 24 * 60 * 60)
      _ -> claims
    end
  end

  def ttl(claims, requested_ttl), do: claims |> iat |> ttl(requested_ttl)
end
