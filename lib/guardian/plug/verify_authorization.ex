defmodule Guardian.Plug.VerifyAuthorization do
  import Guardian.Keys
  import Guardian.CSRFProtection

  def init(opts), do: opts

  def call(conn, opts) do
    key = Dict.get(opts, :key, :default)
    if Guardian.Plug.current_token(conn, key) do
      conn
    else
      verify_token(conn, Plug.Conn.get_req_header(conn, "authorization"), key)
    end
  end

  defp verify_token(conn, [], _), do: conn
  defp verify_token(conn, [token|_], key) do
    case Guardian.verify(token, %{ csrf: fetch_csrf_token(conn) }) do
      { :ok, claims } -> Plug.Conn.assign(conn, claims_key(key), { :ok, claims })
      { :error, reason } -> Plug.Conn.assign(conn, claims_key(key), { :error, reason })
    end
  end

  defp fetch_csrf_token(conn) do
    csrf_from_header(conn) || csrf_from_params(conn) || csrf_from_session(conn)
  end
end
