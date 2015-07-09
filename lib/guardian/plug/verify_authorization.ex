defmodule Guardian.Plug.VerifyAuthorization do
  @moduledoc """
  Use this plug to verify a token contained in the header.

  You should set the value of the Authorization header to:

      Authorization: <jwt>

  ## Example

      plug Guardian.Plug.VerifyAuthorization

  ## Example

      plug Guardian.Plug.VerifyAuthorization, key: :secret

  Verifying the session will update the claims on the request, available with Guardian.Plug.claims/1

  In the case of an error, the claims will be set to { :error, reason }
  """
  import Guardian.Keys

  def init(opts \\ %{}), do: Enum.into(opts, %{})

  def call(conn, opts) do
    key = Dict.get(opts, :key, :default)

    case Guardian.Plug.claims(conn, key) do
      { :ok, _ } -> conn
      { :error, :no_session } -> verify_token(conn, Plug.Conn.get_req_header(conn, "authorization"), key)
      _ -> conn
    end
  end

  defp verify_token(conn, [], _), do: conn
  defp verify_token(conn, [token|_], key) do
    case Guardian.verify(token, %{ }) do
      { :ok, claims } ->
        conn
        |> Plug.Conn.assign(claims_key(key), { :ok, claims })
        |> Plug.Conn.assign(jwt_key(key), token)
      { :error, reason } -> Plug.Conn.assign(conn, claims_key(key), { :error, reason })
    end
  end
end

