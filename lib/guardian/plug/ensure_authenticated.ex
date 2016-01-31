defmodule Guardian.Plug.EnsureAuthenticated do
  @moduledoc """
  This plug ensures that a valid JWT was provided and has been
  verified on the request.

  If one is not found, the `unauthenticated/2` function is invoked with the
  `Plug.Conn.t` object and its params.

  ## Example

      # Will call the unauthenticated/2 function on your handler
      plug Guardian.Plug.EnsureAuthenticated, handler: SomeModule

      # look in the :secret location.  You can also do simple claim checks:
      plug Guardian.Plug.EnsureAuthenticated, handler: SomeModule, key: :secret

      plug Guardian.Plug.EnsureAuthenticated, handler: SomeModule, aud: "token"

  If the handler option is not passed, `Guardian.Plug.ErrorHandler` will provide
  the default behavior.
  """
  require Logger
  import Plug.Conn

  @doc false
  def init(opts) do
    opts = Enum.into(opts, %{})
    handler = build_handler_tuple(opts)

    claims_to_check = Map.drop(opts, [:on_failure, :key, :handler])
    %{
      handler: handler,
      key: Map.get(opts, :key, :default),
      claims: Guardian.Utils.stringify_keys(claims_to_check)
    }
  end

  @doc false
  def call(conn, opts) do
    key = Map.get(opts, :key, :default)

    case Guardian.Plug.claims(conn, key) do
      { :ok, claims } -> conn |> check_claims(opts, claims)
      { :error, reason } -> handle_error(conn, { :error, reason }, opts)
      _ -> handle_error(conn, { :error, :no_session }, opts)
    end
  end

  @doc false
  defp handle_error(conn, reason, opts) do
    the_connection = conn |> assign(:guardian_failure, reason) |> halt

    {mod, meth} = Map.get(opts, :handler)
    apply(
      mod,
      meth,
      [the_connection, Map.merge(the_connection.params, %{ reason: reason })]
    )
  end

  defp check_claims(conn, opts = %{ claims: claims_to_check }, claims) do
    claims_match = claims_to_check
                   |> Map.keys
                   |> Enum.all?(&(claims_to_check[&1] == claims[&1]))
    if claims_match do
      conn
    else
      handle_error(conn, { :error, :claims_do_not_match }, opts)
    end
  end

  defp build_handler_tuple(%{handler: mod}) do
    {mod, :unauthenticated}
  end
  defp build_handler_tuple(%{on_failure: {mod, func}}) do
    Logger.log(
      :warn,
      ":on_failure is deprecated. Use the :handler option instead"
    )
    {mod, func}
  end
  defp build_handler_tuple(_) do
    {Guardian.Plug.ErrorHandler, :unauthenticated}
  end
end
