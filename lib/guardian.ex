defmodule Guardian do
  @moduledoc """
    config :guardian, Guardian,
      issuer: "MyApp",
      ttl: { 30, :days },
      serializer: PhoenixGuardian.GuardianSerializer,
      on_failure: &PhoenixGuardian.SessionController.unauthenticated/2
  """

  if !Dict.get(Application.get_env(:guardian, Guardian), :serializer), do: raise "Guardian requires a serializer"

  def app_claims, do: %{ :iss => issuer } |> issued_at |> default_ttl

  def mint(object, audience), do: mint(object, audience, %{})

  def mint(object, audience, claims) do
    case Guardian.serializer.for_token(object) do
      { :ok, sub } ->
        full_claims = Dict.merge(app_claims, Enum.into(claims, %{}))
        |> Dict.put(:sub, sub)
        |> Dict.put(:aud, audience)

        case Joken.encode(full_claims) do
          { :ok, jwt } -> { :ok, jwt }
          { :error, "Unsupported algorithm" } -> { :error, :unsupported_algorithm }
          { :error, "Error encoding to JSON" } -> { :error, :json_encoding_fail }
        end
      { :error, reason } -> { :error, reason }
    end
  end

  def refresh!(claims), do: Dict.put(claims, :iat, timestamp) |> default_ttl

  def serializer, do: config(:serializer)

  def verify(jwt), do: verify(jwt, %{})

  def verify(jwt, params) do
    if verify_issuer?, do: params = Dict.put_new(params, :iss, issuer)

    try do
      case Joken.decode(jwt, params) do
        { :ok, claims } -> { :ok, claims }
        { :error, "Missing signature" } -> { :error, :missing_signature }
        { :error, "Invalid signature" } -> { :error, :invalid_signature }
        { :error, "Invalid JSON Web Token" } -> { :error, :invalid_jwt }
        { :error, "Token expired" } -> { :error, :token_expired }
        { :error, "Token not valid yet" } -> { :error, :token_not_yet_valid }
        { :error, "Invalid audience" } -> { :error, :invalid_audience }
        { :error, "Missing audience" } -> { :error, :invalid_audience }
        { :error, "Invalid issuer" } -> { :error, :invalid_issuer }
        { :error, "Missing issuer" } -> { :error, :invalid_issuer }
        { :error, "Invalid subject" } -> { :error, :invalid_subject }
        { :error, "Missing subject" } -> { :error, :invalid_subject }
        { :error, reason } -> { :error, reason }
      end
    rescue
      e -> { :error, e.message }
    end
  end

  def verify!(jwt), do: verify!(jwt, %{})

  def verify!(jwt, params) do
    case verify(jwt, params) do
      { :ok, claims } -> claims
      { :error, reason } -> raise reason
    end
  end

  defp issued_at(claims), do: Dict.put_new(claims, :iat, timestamp)

  defp default_ttl(claims) do
    case { Dict.get(claims, :iat), config(:ttl) } do
      { nil, _ } -> Dict.put_new(claims, timestamp + 1_000_000_000)
      { iat, { seconds, :seconds } } -> Dict.put_new(claims, :exp, iat + seconds)
      { iat, { millis, :millis } } -> Dict.put_new(claims, :exp, iat + millis / 1000)
      { iat, { minutes, :minutes } } -> Dict.put_new(claims, :exp, iat + minutes * 60)
      { iat, { hours, :hours } } -> Dict.put_new(claims, :exp, iat + hours * 60 * 60)
      { iat, { days, :days } } -> Dict.put_new(claims, :exp, iat + days * 24 * 60 * 60)
      _ -> claims
    end
  end

  defp timestamp, do: Calendar.DateTime.now("Etc/UTC") |> Calendar.DateTime.Format.unix
  defp issuer, do: config(:issuer, to_string(node))

  defp verify_issuer?, do: config(:verify_issuer, false)

  def config, do: Application.get_env(:guardian, Guardian)
  def config(key), do: Dict.get(config, key)
  def config(key, default), do: Dict.get(config, key, default)
end
