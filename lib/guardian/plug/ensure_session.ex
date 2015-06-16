defmodule Guardian.Plug.EnsureSession do
  def init(opts), do: opts

  def call(conn, opts) do
    key = Dict.get(opts, :key, :default)

    case Guardian.Plug.claims(conn, key) do
      { :ok, claims } -> conn
      { :error, reason } -> handle_error(conn, { :error, reason }, opts)
      stuff -> handle_error(conn, { :error, :no_session }, opts)
    end
  end

  defp handle_error(conn, reason, opts) do
    failer = Dict.get(opts, :on_failure, Guardian.config(:on_failure))
    conn
    |> Plug.Conn.assign(:guardian_failure, reason)
    |> Plug.Conn.halt
    |> failer.(conn.params)
  end
end

