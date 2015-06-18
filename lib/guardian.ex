defmodule Guardian do
  @moduledoc """
    A module that provides JWT based authentication for Elixir applications.

    Guardian provides the framework for using JWT any elixir application, web based or otherwise,
    Where authentication is required.

    The base unit of authentication currency is implemented using JWTs.

    ## Configuration

        config :guardian, Guardian,
          issuer: "MyApp",
          ttl: { 30, :days },
          secret_key: "lksdjowiurowieurlkjsdlwwer",
          serializer: MyApp.GuardianSerializer

    Guardian usese Joken, so you will also need to configure that.
  """
  import Guardian.Utils

  if !Application.get_env(:guardian, Guardian), do: raise "Guardian is not configured"
  if !Dict.get(Application.get_env(:guardian, Guardian), :serializer), do: raise "Guardian requires a serializer"

  # make our atoms that we know we need


  @doc """
    Mint a JWT from a resource. The resource will be run through the configured serializer to obtain a value suitable for storage inside a JWT.
  """
  @spec mint(any) :: { :ok, String.t, Map } | { :error, atom } | { :error, String.t }
  def mint(object), do: mint(object, nil, %{})

  @doc """
    Like mint/1 but also accepts the audience (encoded to the aud key) for the JWT

    The aud can be anything but suggested is "token".

    The "csrf" audience is special in that it will encode the CSRF token into the JWT. Thereafter whenver verifying the JWT, the CSRF token must be given, and must match.
  """
  @spec mint(any, atom | String.t) :: { :ok, String.t, Map } | { :error, atom } | { :error, String.t }
  def mint(object, audience), do: mint(object, audience, %{})

  @doc """
    Like mint/2 but also encode anything found inside the claims map into the JWT.
  """
  @spec mint(any, atom | String.t, Map) :: { :ok, String.t, Map } | { :error, atom } | { :error, String.t }
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

  @doc """
    Fetch the configured serializer module
  """
  @spec serializer() :: Module.t
  def serializer, do: config(:serializer)

  @doc """
    Verify the given JWT. This will verify via verify/2
  """
  @spec verify(String.t) :: { :ok, Map } | { :error, atom } | { :error, String.t }
  def verify(jwt), do: verify(jwt, %{})


  @doc """
    Verify the given JWT.

    If the CSRF token type is used, you must pass at least %{ csrf: <token } as the params
  """
  @spec verify(String.t, Map) :: { :ok, Map } | { :error, atom | String.t }
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

  @doc """
    If successfully verified, returns the claims encoded into the JWT. Raises otherwise
  """
  @spec verify!(String.t) :: Map
  def verify!(jwt), do: verify!(jwt, %{})

  @doc """
    If successfully verified, returns the claims encoded into the JWT. Raises otherwise

    If the token type is "csrf" the params must contain %{ csrf: csrf_token }
  """
  @spec verify!(String.t, Map) :: Map
  def verify!(jwt, params) do
    case verify(jwt, params) do
      { :ok, claims } -> claims
      { :error, reason } -> raise to_string(reason)
    end
  end

  @doc """
    The configured issuer. If not configured, defaults to the node that issued.
  """
  @spec issuer() :: String.t
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

  @doc false
  def config, do: Application.get_env(:guardian, Guardian)
  @doc false
  def config(key), do: Dict.get(config, key)
  @doc false
  def config(key, default), do: Dict.get(config, key, default)
end
