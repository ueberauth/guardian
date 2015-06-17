defmodule Guardian.Plug.EnsureSession do
  def init(opts) do
    IO.inspect(opts)
    case Dict.get(opts, :on_failure) do
      { _mod, _meth } -> opts
      _ -> raise "Requires an on_failure function { Mod, :function_name }"
    end
  end

  def call(conn, opts) do
    key = Dict.get(opts, :key, :default)

    case Guardian.Plug.claims(conn, key) do
      { :ok, claims } -> conn
      { :error, reason } -> handle_error(conn, { :error, reason }, opts)
      _ -> handle_error(conn, { :error, :no_session }, opts)
    end
  end

  defp handle_error(conn, reason, opts) do
    the_connection = conn |> Plug.Conn.assign(:guardian_failure, reason) |> Plug.Conn.halt

    { mod, func } = Dict.get(opts, :on_failure)
    apply(mod, func, [the_connection, the_connection.params])
  end
end

