defmodule Guardian do
  @moduledoc """
  A module that provides JWT based authentication for Elixir applications.

  Guardian provides the framework for using JWT in any Elixir application,
  web based or otherwise, where authentication is required.

  The base unit of authentication currency is implemented using JWTs.

  ## Configuration

      config :guardian, Guardian,
        allowed_algos: ["HS512", "HS384"],
        issuer: "MyApp",
        ttl: { 30, :days },
        serializer: MyApp.GuardianSerializer,
        secret_key: "lksjdlkjsdflkjsdf"

  """
  import Guardian.Utils

  @default_algos ["HS512"]
  @default_token_type "access"

  @doc """
  Returns the current default token type.
  """
  def default_token_type, do: @default_token_type

  @doc """
  Encode and sign a JWT from a resource.
  The resource will be run through the configured serializer
  to obtain a value suitable for storage inside a JWT.
  """
  @spec encode_and_sign(any) :: {:ok, String.t, map} |
                                {:error, any}
  def encode_and_sign(object), do: encode_and_sign(object, @default_token_type, %{})

  @doc """
  Like encode_and_sign/1 but also accepts the type (encoded to the typ key)
  for the JWT

  The type can be anything but suggested is "access".
  """
  @spec encode_and_sign(any, atom | String.t) :: {:ok, String.t, map} |
                                                 {:error, any}
  def encode_and_sign(object, type), do: encode_and_sign(object, type, %{})

  @doc false
  def encode_and_sign(object, type, claims) when is_list(claims) do
    encode_and_sign(object, type, Enum.into(claims, %{}))
  end

  @doc """
  Like encode_and_sign/2 but also encode anything found
  inside the claims map into the JWT.

  To encode permissions into the token, use the `:perms` key
  and pass it a map with the relevant permissions (must be configured)

  ### Example

      Guardian.encode_and_sign(
        user,
        :access,
        perms: %{ default: [:read, :write] }
      )
  """
  @spec encode_and_sign(any, atom | String.t, map) :: {:ok, String.t, map} |
                                                      {:error, any}
  def encode_and_sign(object, type, claims) do
    case build_claims(object, type, claims) do
      {:ok, claims_for_token} ->

        called_hook = call_before_encode_and_sign_hook(
          object,
          type,
          claims_for_token
        )

        encode_from_hooked(called_hook)

      {:error, reason} -> {:error, reason}
    end
  end

  defp encode_from_hooked({:ok, {resource, type, claims_from_hook}}) do
    {:ok, jwt} = encode_claims(claims_from_hook)
    case call_after_encode_and_sign_hook(
      resource,
      type,
      claims_from_hook, jwt
    ) do
      {:ok, _} -> {:ok, jwt, claims_from_hook}
      {:error, reason} -> {:error, reason}
    end
  end

  defp encode_from_hooked({:error, _reason} = error), do: error

  @doc false
  def hooks_module, do: config(:hooks, Guardian.Hooks.Default)

  @doc """
  Revokes the current token.
  This provides a hook to revoke.
  The logic for revocation of belongs in a Guardian.Hook.on_revoke
  This function is less efficient that revoke!/2.
  If you have claims, you should use that.
  """
  @spec revoke!(String.t, map) :: :ok | {:error, any}
  def revoke!(jwt, params \\ %{}) do
    case decode_and_verify(jwt, params) do
      {:ok, claims} -> revoke!(jwt, claims, params)
      _ -> :ok
    end
  end

  @doc """
  Revokes the current token.
  This provides a hook to revoke.
  The logic for revocation of belongs in a Guardian.Hook.on_revoke
  """
  @spec revoke!(String.t, map, map) :: :ok | {:error, any}
  def revoke!(jwt, claims, _params) do
    case Guardian.hooks_module.on_revoke(claims, jwt) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Refresh the token. The token will be renewed and receive a new:

  * `jti` - JWT id
  * `iat` - Issued at
  * `exp` - Expiry time.
  * `nbf` - Not valid before time

  The current token will be revoked when the new token is successfully created.

  Note: A valid token must be used in order to be refreshed.
  """
  @spec refresh!(String.t) :: {:ok, String.t, map} | {:error, any}
  def refresh!(jwt), do: refresh!(jwt, %{}, %{})


  @doc """
  As refresh!/1 but allows the claims to be updated.
  Specifically useful is the ability to set the ttl of the token.

      Guardian.refresh(existing_jwt, existing_claims, %{ttl: { 5, :minutes}})

  Once the new token is created, the old one will be revoked.
  """
  @spec refresh!(String.t, map, map) :: {:ok, String.t, map} |
                                            {:error, any}
  def refresh!(jwt, claims, params \\ %{}) do
    case decode_and_verify(jwt, params) do
      {:ok, found_claims} ->
        do_refresh!(jwt, Map.merge(found_claims, claims), params)
      {:error, reason} -> {:error, reason}
    end
  end

  defp do_refresh!(original_jwt, original_claims, params) do
    params = Enum.into(params, %{})
    new_claims = original_claims
     |> Map.drop(["jti", "iat", "exp", "nbf"])
     |> Map.merge(params)
     |> Guardian.Claims.jti
     |> Guardian.Claims.nbf
     |> Guardian.Claims.iat
     |> Guardian.Claims.ttl

    type = Map.get(new_claims, "typ")

    {:ok, resource} = Guardian.serializer.from_token(new_claims["sub"])

    case encode_and_sign(resource, type, new_claims) do
      {:ok, jwt, full_claims} ->
        _ = revoke!(original_jwt, peek_claims(original_jwt), %{})
        {:ok, jwt, full_claims}
      {:error, reason} -> {:error, reason}
    end
  end


  @doc """
  Exchange a token with type 'from_type' for a token with type 'to_type', the
  claims(apart from "jti", "iat", "exp", "nbf" and "typ) will persists though the
  exchange
  Can be used to get an access token from a refresh token

      Guardian.exchange(existing_jwt, "refresh", "access")

  The old token wont be revoked after the exchange
  """
  @spec exchange(String.t, String.t, String.t) :: {:ok, String.t, Map} |
                                                  {:error, any}

  def exchange(old_jwt, from_typ, to_typ) do
    case decode_and_verify(old_jwt) do
      {:ok, found_claims} -> do_exchange(from_typ, to_typ, found_claims)
      {:error, reason} -> {:error, reason}
    end
  end

  @doc false
  defp do_exchange(from_typ, to_typ, original_claims) do
    if correct_typ?(original_claims, from_typ) do
      {:ok, resource} = Guardian.serializer.from_token(original_claims["sub"])
      new_claims = original_claims
       |> Map.drop(["jti", "iat", "exp", "nbf", "typ"])
      case encode_and_sign(resource, to_typ, new_claims) do
        {:ok, jwt, full_claims} -> {:ok, jwt, full_claims}
        {:error, reason} -> {:error, reason}
      end
    else
      {:error, :incorrect_token_type}
    end
  end

  @doc false
  defp correct_typ?(claims, typ) when is_binary(typ) do
    Map.get(claims, "typ") === typ
  end

  @doc false
  defp correct_typ?(claims, typ) when is_atom(typ) do
    Map.get(claims, "typ") === to_string(typ)
  end

  @doc false
  defp correct_typ?(claims, typ_list) when is_list(typ_list) do
    typ = Map.get(claims, "typ")
    typ_list |> Enum.any?(&(&1 === typ))
  end

  @doc false
  defp correct_typ?(_claims, _typ) do
    false
  end


  @doc """
  Fetch the configured serializer module
  """
  @spec serializer() :: atom
  def serializer, do: config(:serializer)

  @doc """
  Verify the given JWT. This will decode_and_verify via decode_and_verify/2
  """
  @spec decode_and_verify(String.t) :: {:ok, map} |
                                       {:error, any}
  def decode_and_verify(jwt), do: decode_and_verify(jwt, %{})


  @doc """
  Verify the given JWT.
  """
  @spec decode_and_verify(String.t, map) :: {:ok, map} |
                                            {:error, any}
  def decode_and_verify(jwt, params) do
    params = if verify_issuer?() do
      params
      |> stringify_keys
      |> Map.put_new("iss", issuer())
    else
      params
    end
    params = stringify_keys(params)
    {secret, params} = strip_value(params, "secret")

    try do
      with {:ok, claims} <- decode_token(jwt, secret),
           {:ok, verified_claims} <- verify_claims(claims, params),
           {:ok, {claims, _}} <- Guardian.hooks_module.on_verify(verified_claims, jwt),
        do: {:ok, claims}
    rescue
      e ->
        {:error, e}
    end
  end

  @doc """
  If successfully verified, returns the claims encoded into the JWT.
  Raises otherwise
  """
  @spec decode_and_verify!(String.t) :: map
  def decode_and_verify!(jwt), do: decode_and_verify!(jwt, %{})

  @doc """
  If successfully verified, returns the claims encoded into the JWT.
  Raises otherwise
  """
  @spec decode_and_verify!(String.t, map) :: map
  def decode_and_verify!(jwt, params) do
    case decode_and_verify(jwt, params) do
      {:ok, claims} -> claims
      {:error, reason} -> raise to_string(reason)
    end
  end

  @doc """
  The configured issuer. If not configured, defaults to the node that issued.
  """
  @spec issuer() :: String.t
  def issuer, do: config(:issuer, to_string(node()))

  defp verify_issuer?, do: config(:verify_issuer, false)

  @doc false
  def config do
    :guardian
    |> Application.get_env(Guardian)
    |> check_config
  end

  @doc false
  def check_config(nil), do: raise "Guardian is not configured"
  def check_config(cfg) do
    case Keyword.has_key?(cfg, :serializer) do
      false -> raise "Guardian requires a serializer"
      true  -> cfg
    end
  end

  @doc false
  def config(key, default \\ nil),
    do: config() |> Keyword.get(key, default) |> resolve_config(default)

  defp resolve_config({:system, var_name}, default),
    do: System.get_env(var_name) || default
  defp resolve_config(value, _default),
    do: value

  @doc """
  Read the header of the token.
  This is not a verified read, it does not check the signature.
  """
  def peek_header(token) do
    JOSE.JWT.peek_protected(token).fields
  end

  @doc """
  Read the claims of the token.
  This is not a verified read, it does not check the signature.
  """
  def peek_claims(token) do
    JOSE.JWT.peek_payload(token).fields
  end

  defp jose_jws(headers) do
    Map.merge(%{"alg" => hd(allowed_algos())}, headers)
  end

  defp jose_jwk(the_secret = %JOSE.JWK{}), do: the_secret
  defp jose_jwk(the_secret) when is_binary(the_secret), do: JOSE.JWK.from_oct(the_secret)
  defp jose_jwk(the_secret) when is_map(the_secret), do: JOSE.JWK.from_map(the_secret)
  defp jose_jwk({mod, fun}),       do: jose_jwk(:erlang.apply(mod, fun, []))
  defp jose_jwk({mod, fun, args}), do: jose_jwk(:erlang.apply(mod, fun, args))
  defp jose_jwk(nil), do: jose_jwk(config(:secret_key) || false)

  defp encode_claims(claims) do
    {headers, claims} = strip_value(claims, "headers", %{})
    {secret, claims} = strip_value(claims, "secret")
    {_, token} = secret
                   |> jose_jwk()
                   |> JOSE.JWT.sign(jose_jws(headers), claims)
                   |> JOSE.JWS.compact
    {:ok, token}
  end

  defp decode_token(token, secret) do
    secret = secret || config(:secret_key)
    case JOSE.JWT.verify_strict(jose_jwk(secret), allowed_algos(), token) do
      {true, jose_jwt, _} ->  {:ok, jose_jwt.fields}
      {false, _, _} -> {:error, :invalid_token}
    end
  end

  defp allowed_algos, do: config(:allowed_algos, @default_algos)

  def verify_claims(claims, params) do
    verify_claims(
      claims,
      Map.keys(claims),
      config(:verify_module, Guardian.JWT),
      params
    )
  end

  defp verify_claims(claims, [h | t], module, params) do
    case apply(module, :validate_claim, [h, claims, params]) do
      :ok -> verify_claims(claims, t, module, params)
      {:error, reason} -> {:error, reason}
    end
  end

  defp verify_claims(claims, [], _, _), do: {:ok, claims}

  defp build_claims(object, type, claims) do
    case Guardian.serializer.for_token(object) do
      {:ok, sub} ->
        full_claims = claims
                      |> stringify_keys
                      |> set_permissions
                      |> Guardian.Claims.app_claims
                      |> Guardian.Claims.typ(type)
                      |> Guardian.Claims.sub(sub)
                      |> set_ttl
                      |> set_aud_if_nil(sub)

        {:ok, full_claims}
      {:error, reason} ->  {:error, reason}
    end
  end

  defp call_before_encode_and_sign_hook(object, type, claims) do
    Guardian.hooks_module.before_encode_and_sign(object, type, claims)
  end

  defp call_after_encode_and_sign_hook(resource, type, claims, jwt) do
    Guardian.hooks_module.after_encode_and_sign(resource, type, claims, jwt)
  end

  defp set_permissions(claims) do
    perms = Map.get(claims, "perms", %{})

    claims
    |> Guardian.Claims.permissions(perms)
    |> Map.delete("perms")
  end

  defp set_ttl(claims) do
    claims
    |> Guardian.Claims.ttl
    |> Map.delete("ttl")
  end

  def set_aud_if_nil(claims, value) do
    if Map.get(claims, "aud") == nil do
      Guardian.Claims.aud(claims, value)
    else
      claims
    end
  end

  defp strip_value(map, key, default \\ nil) do
    value = Map.get(map, key, default)
    {value, Map.drop(map, [key])}
  end
end
