defmodule Guardian.Plug.EnsureAuthenticated do
  @moduledoc """
  This plug ensures that a valid JWT was provided and has been verified on the request.

  If one is not found, the on\_failure function is invoked with the Plug.Conn.t object and it's params.

  ## Example

      plug Guardian.Plug.EnsureAuthenticated, on_failure: { SomeModule, :some_method } # look in the default location
      plug Guardian.Plug.EnsureAuthenticated, on_failure: { SomeModule, :some_method }, key: :secret # look in the :secret location

  The on\_failure option must be passed. The corresponding function will be called with the Plug.Conn.t and it's params.
  """

  @doc false
  def init(opts) do
    opts = Enum.into(opts, %{})
    case Dict.get(opts, :on_failure) do
      { _mod, _meth } -> opts
      _ -> raise "Requires an on_failure function { Mod, :function_name }"
    end
  end

  @doc false
  def call(conn, opts) do
    key = Dict.get(opts, :key, :default)

    case Guardian.Plug.claims(conn, key) do
      { :ok, _ } -> conn
      { :error, reason } -> handle_error(conn, { :error, reason }, opts)
      _ -> handle_error(conn, { :error, :no_session }, opts)
    end
  end

  @doc false
  defp handle_error(conn, reason, opts) do
    the_connection = conn |> Plug.Conn.assign(:guardian_failure, reason) |> Plug.Conn.halt

    { mod, func } = Dict.get(opts, :on_failure)
    apply(mod, func, [the_connection, the_connection.params])
  end
end

