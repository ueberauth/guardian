defmodule Guardian.Plug.VerifyAuthorization do
  import Guardian.Keys

  def init(opts), do: opts

  def call(conn, opts) do
    key = Dict.get(opts, :key, :default)
    verify_token(conn, Plug.Conn.get_req_header(conn, "authorization"), key)
  end

  defp verify_token(conn, [], _), do: conn
  defp verify_token(conn, [token|_], key) do
    case Guardian.verify(token) do
      { :ok, claims } ->
        Plug.Conn.assign(conn, claims_key(key), { :ok, claims })
      { :error, reason } ->
        Plug.Conn.assign(conn, claims_key(key), { :error, reason })
    end
  end
end
