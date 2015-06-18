defmodule Guardian do
  @moduledoc """
    config :guardian, Guardian,
      issuer: "MyApp",
      ttl: { 30, :days },
      serializer: PhoenixGuardian.GuardianSerializer,
      on_failure: &PhoenixGuardian.SessionController.unauthenticated/2
  """
  import Guardian.Utils

  if !Application.get_env(:guardian, Guardian), do: raise "Guardian is not configured"
  if !Dict.get(Application.get_env(:guardian, Guardian), :serializer), do: raise "Guardian requires a serializer"

  # make our atoms that we know we need


  def mint(object), do: mint(object, nil, %{})
  def mint(object, audience), do: mint(object, audience, %{})
  def mint(object, audience, claims) do
    if audience == :csrf || audience == "csrf" do
      csrf_token = Dict.get(claims, :csrf, Dict.get(claims, "csrf"))
      if !csrf_token, do: raise "No CSRF token found"
      claims = Guardian.Claims.csrf(claims, csrf_token)
    end

    case Guardian.serializer.for_token(object) do
      { :ok, sub } ->
        full_claims = Guardian.Claims.app_claims(claims)
        |> Guardian.Claims.aud(audience)
        |> Guardian.Claims.sub(sub)

        case Joken.encode(full_claims) do
          { :ok, jwt } -> { :ok, jwt, full_claims }
          { :error, "Unsupported algorithm" } -> { :error, :unsupported_algorithm }
          { :error, "Error encoding to JSON" } -> { :error, :json_encoding_fail }
        end
      { :error, reason } -> { :error, reason }
    end
  end

  def serializer, do: config(:serializer)

  def verify(jwt), do: verify(jwt, %{})

  def verify(jwt, params) do
    if verify_issuer?, do: params = Dict.put_new(params, :iss, issuer)

    check_params = Dict.delete(params, :s_csrf)

    try do
      case Joken.decode(jwt, check_params) do
        { :ok, claims } -> verify_claims!(claims, params)
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
      e ->
        IO.puts(Exception.format_stacktrace(System.stacktrace))
        { :error, e.message }
    end
  end

  def verify!(jwt), do: verify!(jwt, %{})

  def verify!(jwt, params) do
    case verify(jwt, params) do
      { :ok, claims } -> claims
      { :error, reason } -> raise to_string(reason)
    end
  end

  def issuer, do: config(:issuer, to_string(node))

  defp verify_claims!(claims = %{ aud: "csrf"}, nil), do: { :error, :invalid_csrf }
  defp verify_claims!(claims = %{ aud: "csrf"}, params), do: verify_claims!(claims, claims.s_csrf, params)

  defp verify_claims!(claims = %{ aud: "csrf" }, nil, _), do: { :error, :invalid_csrf }
  defp verify_claims!(claims = %{ aud: "csrf" }, signed, params) do
    if Guardian.CSRFProtection.verify(signed, Dict.get(params, :csrf, Dict.get(params, "csrf"))) do
      { :ok, claims }
    else
      { :error, :invalid_csrf }
    end
  end

  defp verify_claims!(claims, _), do: { :ok, claims }

  defp verify_issuer?, do: config(:verify_issuer, false)

  def config, do: Application.get_env(:guardian, Guardian)
  def config(key), do: Dict.get(config, key)
  def config(key, default), do: Dict.get(config, key, default)

end
