defmodule Guardian.Plug.EnsureAuthenticated do
  @moduledoc """
  This plug ensures that a valid JWT was provided and has been verified on the request.

  If one is not found, the on\_failure function is invoked with the Plug.Conn.t object and it's params.

  ## Example

      plug Guardian.Plug.EnsureAuthenticated, handler: SomeModule # Will call the unauthenticated function on your handler
      plug Guardian.Plug.EnsureAuthenticated, handler: SomeModule, key: :secret # look in the :secret location.  You can also do simple claim checks:
      plug Guardian.Plug.EnsureAuthenticated, handler: SomeModule, aud: "token"

  The handler option may be passed. By default Guardian.Plug.ErrorHandler is used and the `:unauthenticated` function will be called.

  The handler will be called on failure.
  The `:unauthenticated` function will be called when a failure is detected.
  """
  require Logger
  import Plug.Conn

  @doc false
  def init(opts) do
    opts = Enum.into(opts, %{})
    handler = case Map.get(opts, :handler) do
      mod when mod != nil ->
        {mod, :unauthenticated}
      nil ->
        case Map.get(opts, :on_failure) do
          {mod, f} ->
            Logger.log(:warn, "on_failure is deprecated. Use handler instead")
            {mod, f}
        _ -> raise "Requires a handler module to be passed"
        end
    end

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
    apply(mod, meth, [the_connection, Map.merge(the_connection.params, %{ reason: reason })])
  end

  defp check_claims(conn, opts = %{ claims: claims_to_check }, claims) do
    claims_match = Map.keys(claims_to_check) |> Enum.all?(&(claims_to_check[&1] == claims[&1]))
    if claims_match, do: conn, else: handle_error(conn, { :error, :claims_do_not_match }, opts)
  end

  defp check_claims(conn, _, _), do: conn
end

