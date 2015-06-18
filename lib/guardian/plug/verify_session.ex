defmodule Guardian.Plug.VerifySession do
  import Guardian.Keys
  import Guardian.CSRFProtection

  def init(opts), do: opts

  def call(conn, opts) do
    key = Dict.get(opts, :key, :default)
    jwt = Plug.Conn.get_session(conn, base_key(key))

    if jwt do
      case Guardian.verify(jwt, %{ csrf: fetch_csrf_token(conn) }) do
        { :ok, claims } ->
          conn
          |> Guardian.Plug.set_claims({ :ok, claims }, key)
          |> Guardian.Plug.set_current_token(jwt, key)
        { :error, reason } ->
          conn
          |> Plug.Conn.delete_session(base_key(key))
          |> Guardian.Plug.set_claims({ :error, reason }, key)
      end
    else
      conn
    end
  end

  defp fetch_csrf_token(conn) do
    csrf_from_header(conn) || csrf_from_params(conn) || csrf_from_session(conn)
  end
end
