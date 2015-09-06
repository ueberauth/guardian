defmodule Guardian.Claims do
  @moduledoc false
  import Guardian.Utils

  @doc false
  def app_claims, do: %{ "iss" => Guardian.issuer } |> iat |> ttl |> jti

  @doc false
  def app_claims(existing_claims) do
    Map.merge(app_claims, Enum.into(existing_claims, %{}))
  end

  @doc """
  Encodes permissions into the claims set. Permissions are stored at the :pem key
  as a map of <type> => <value as int>
  """
  def permissions(claims, permissions) do
    perms = Enum.into(%{}, permissions)
    |> Enum.reduce(%{}, fn({key, list}, acc) ->
      Map.put(acc, to_string(key), Guardian.Permissions.to_value(list, key))
    end)
    Map.put(claims, "pem", perms)
  end

  @doc false
  def aud(claims, nil), do: aud(claims, "token")
  @doc false
  def aud(claims, audience) when is_atom(audience), do: aud(claims, to_string(audience))
  @doc false
  def aud(claims, audience), do: Map.put(claims, "aud", audience)

  @doc false
  def sub(claims, subject) when is_atom(subject), do: sub(claims, to_string(subject))
  @doc false
  def sub(claims, subject), do: Map.put(claims, "sub", subject)

  @doc false
  def jti(claims), do: jti(claims, UUID.uuid4)
  @doc false
  def jti(claims, id) when is_atom(id), do: sub(claims, to_string(id))
  @doc false
  def jti(claims, id), do: Map.put(claims, "jti", id)

  @doc false
  def iat(claims), do: Map.put(claims, "iat", timestamp)
  @doc false
  def iat(claims, ts), do: Map.put(claims, "iat", ts)

  @doc false
  def ttl(claims = %{ ttl: requested_ttl }) do
    claims
    |> Map.delete(:ttl)
    |> ttl(requested_ttl)
  end

  @doc false
  def ttl(claims), do: ttl(claims, Guardian.config(:ttl, { 1_000_000_000, :seconds }))

  @doc false
  def ttl(claims = %{"iat" => iat}, requested_ttl) do
    case { iat, requested_ttl } do
      { nil, _ } -> Map.put_new(claims, timestamp + 1_000_000_000)
      { iat, { seconds, :seconds } } -> Map.put(claims, "exp", iat + seconds)
      { iat, { seconds, :second } } -> Map.put(claims, "exp", iat + seconds)
      { iat, { millis, :millis } } -> Map.put(claims, "exp", iat + millis / 1000)
      { iat, { millis, :milli } } -> Map.put(claims, "exp", iat + millis / 1000)
      { iat, { minutes, :minutes } } -> Map.put(claims, "exp", iat + minutes * 60)
      { iat, { minutes, :minute } } -> Map.put(claims, "exp", iat + minutes * 60)
      { iat, { hours, :hours } } -> Map.put(claims, "exp", iat + hours * 60 * 60)
      { iat, { hours, :hour } } -> Map.put(claims, "exp", iat + hours * 60 * 60)
      { iat, { days, :days } } -> Map.put(claims, "exp", iat + days * 24 * 60 * 60)
      { iat, { days, :day } } -> Map.put(claims, "exp", iat + days * 24 * 60 * 60)
      _ -> claims
    end
  end

  @doc false
  def ttl(claims, requested_ttl), do: claims |> iat |> ttl(requested_ttl)
end
