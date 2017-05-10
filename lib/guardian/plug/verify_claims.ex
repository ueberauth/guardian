defmodule Guardian.Plug.VerifyClaims do
  @moduledoc """
  Use this plug to verify and load claims contained in a session.

  ## Example

      plug Guardian.Plug.VerifyClaims

  You can also specify a location to look for the claims

  ## Example

      plug Guardian.Plug.VerifyClaims, key: :secret

  Loading the claims will make them available on the connecion, available
  with Guardian.Plug.claims/1

  In the case of an error, the claims will be set to { :error, reason }
  """
  import Guardian.Keys
  import Guardian.Utils

  @doc false
  def init(opts \\ %{}), do: Enum.into(opts, %{})

  @doc false
  def call(conn, opts) do
    key = Map.get(opts, :key, :default)

    case Guardian.Plug.claims(conn, key) do
      {:ok, _} -> conn
      {:error, _} ->
        claims = Plug.Conn.get_session(conn, base_key(key))

        if claims do
          case decode_and_verify(claims, %{}) do
            {:ok, claims} ->
              conn
              |> Guardian.Plug.set_claims({:ok, claims}, key)
            {:error, reason} ->
              conn
              |> Plug.Conn.delete_session(base_key(key))
              |> Guardian.Plug.set_claims({:error, reason}, key)
          end
        else
          conn
        end
    end
  end

  @doc """
  Verify the given claims. This will decode_and_verify via decode_and_verify/2
  """
  @spec decode_and_verify(map) :: {:ok, map} |
                                       {:error, any}
  def decode_and_verify(claims), do: decode_and_verify(claims, %{})

  @doc """
  Verify the given claims.
  """
  @spec decode_and_verify(map, map) :: {:ok, map} | {:error, any}
  def decode_and_verify(claims, params) do
    params = if verify_issuer?() do
      params
      |> stringify_keys
      |> Map.put_new("iss", Guardian.issuer())
    else
      params
    end
    params = stringify_keys(params)

    # try do
      with {:ok, verified_claims} <- Guardian.verify_claims(claims, params),
           {:ok, {claims, _}} <- Guardian.hooks_module.on_verify(verified_claims, nil),
        do: {:ok, claims}
    # rescue
    #   e ->
    #     {:error, e}
    # end
  end

  defp verify_issuer?, do: Guardian.config(:verify_issuer, false)
end
