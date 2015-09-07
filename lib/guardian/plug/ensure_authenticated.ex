defmodule Guardian.Plug.EnsureAuthenticated do
  @moduledoc """
  This plug ensures that a valid JWT was provided and has been verified on the request.

  If one is not found, the on\_failure function is invoked with the Plug.Conn.t object and it's params.

  ## Example

      plug Guardian.Plug.EnsureAuthenticated, on_failure: { SomeModule, :some_method } # look in the default location
      plug Guardian.Plug.EnsureAuthenticated, on_failure: { SomeModule, :some_method }, key: :secret # look in the :secret location

  You can also do simple claim checks:
      plug Guardian.Plug.EnsureAuthenticated, on_failure: { SomeModule, :some_method }, aud: "token"

  The on\_failure option must be passed. The corresponding function will be called with the Plug.Conn.t and it's params.
  """

  @doc false
  def init(opts) do
    opts = Enum.into(opts, %{})
    case Map.get(opts, :on_failure) do
      { _mod, _meth } ->
        claims_to_check = opts |> Map.delete(:on_failure) |> Map.delete(:key)
        %{
          on_failure: Map.get(opts, :on_failure),
          key: Map.get(opts, :key, :default),
          claims: Guardian.Utils.stringify_keys(claims_to_check)
        }
      _ -> raise "Requires an on_failure function { Mod, :function_name }"
    end
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
    the_connection = conn |> Plug.Conn.assign(:guardian_failure, reason) |> Plug.Conn.halt

    { mod, func } = Map.get(opts, :on_failure)
    apply(mod, func, [the_connection, the_connection.params])
  end

  defp check_claims(conn, opts = %{ claims: claims_to_check }, claims) do
    claims_match = Map.keys(claims_to_check) |> Enum.map(&(claims_to_check[&1] == claims[&1])) |> Enum.all?
    if claims_match, do: conn, else: handle_error(conn, { :error, :claims_do_not_match }, opts)
  end

  defp check_claims(conn, _, _), do: conn
end

