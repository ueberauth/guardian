defmodule Guardian.Plug.VerifySession do
  def init(opts), do: opts

  def call(conn, opts) do
    key = Dict.get(opts, :key, :default)
    jwt = Plug.Conn.get_session(conn, Guardian.Plug.base_key(key))

    if jwt do
      case Guardian.verify(jwt) do
        { :ok, claims } ->
          conn
          |> Guardian.Plug.set_claims({ :ok, claims }, key)
          |> Guardian.Plug.set_current_token(jwt, key)
        { :error, reason } ->
          conn
          |> Plug.Conn.delete_session(Guardian.Plug.base_key(key))
          |> Guardian.Plug.set_claims({ :error, reason }, key)
      end
    else
      conn
    end
  end
end
