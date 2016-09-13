defmodule Guardian.Plug.VerifyHeader do
  @moduledoc """
  Use this plug to verify a token contained in the header.

  You should set the value of the Authorization header to:

      Authorization: <jwt>

  ## Example

      plug Guardian.Plug.VerifyHeader

  ## Example

      plug Guardian.Plug.VerifyHeader, key: :secret

  Verifying the session will update the claims on the request,
  available with Guardian.Plug.claims/1

  In the case of an error, the claims will be set to { :error, reason }

  A "realm" can be specified when using the plug.
  Realms are like the name of the token and allow many tokens
  to be sent with a single request.

      plug Guardian.Plug.VerifyHeader, realm: "Bearer"

  When a realm is not specified,
  the first authorization header found is used, and assumed to be a raw token

  #### example

      plug Guardian.Plug.VerifyHeader

      # will take the first auth header
      # Authorization: <jwt>
  """

  def init(opts \\ %{}) do
    opts_map = Enum.into(opts, %{})
    realm = Map.get(opts_map, :realm)
    if realm do
      {:ok, reg} = Regex.compile("#{realm}\:?\s+(.*)$", "i")
      Map.put(opts_map, :realm_reg, reg)
    else
      opts_map
    end
  end

  def call(conn, opts) do
    key = Map.get(opts, :key, :default)

    case Guardian.Plug.claims(conn, key) do
      {:ok, _} -> conn
      {:error, :no_session} ->
        verify_token(conn, fetch_token(conn, opts), key)
      _ -> conn
    end
  end

  defp verify_token(conn, nil, _), do: conn
  defp verify_token(conn, "", _), do: conn

  defp verify_token(conn, token, key) do
    case Guardian.decode_and_verify(token, %{}) do
      {:ok, claims} ->
        conn
        |> Guardian.Plug.set_claims({:ok, claims}, key)
        |> Guardian.Plug.set_current_token(token, key)
      {:error, reason} ->
        Guardian.Plug.set_claims(conn,{:error, reason}, key)
    end
  end

  defp fetch_token(conn, opts) do
    fetch_token(conn, opts, Plug.Conn.get_req_header(conn, "authorization"))
  end

  defp fetch_token(_, _, []), do: nil

  defp fetch_token(conn, opts = %{realm_reg: reg}, [token|tail]) do
    trimmed_token = String.strip(token)
    case Regex.run(reg, trimmed_token) do
      [_, match] -> String.strip(match)
      _ -> fetch_token(conn, opts, tail)
    end
  end

  defp fetch_token(_, _, [token|_tail]), do: String.strip(token)
end
