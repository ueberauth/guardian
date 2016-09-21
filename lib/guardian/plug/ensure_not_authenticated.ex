defmodule Guardian.Plug.EnsureNotAuthenticated do
  @moduledoc """
  This plug ensures that a invalid JWT was provided and has been
  verified on the request.

  If one is found, the `already_authenticated/2` function is invoked with the
  `Plug.Conn.t` object and its params.

  ## Example

      # Will call the already_authenticated/2 function on your handler
      plug Guardian.Plug.EnsureNotAuthenticated, handler: SomeModule

      # look in the :secret location.  You can also do simple claim checks:
      plug Guardian.Plug.EnsureNotAuthenticated, handler: SomeModule,
                                                 key: :secret

      plug Guardian.Plug.EnsureNotAuthenticated, handler: SomeModule,
                                                 aud: "token"

  If the handler option is not passed, `Guardian.Plug.ErrorHandler` will provide
  the default behavior.
  """
  require Logger
  import Plug.Conn

  @doc false
  def init(opts) do
    opts = Enum.into(opts, %{})
    handler = build_handler_tuple(opts)

    claims_to_check = Map.drop(opts, [:key, :handler])
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
      {:ok, claims} -> conn |> check_claims(opts, claims)
      {:error, _reason} -> conn
    end
  end

  @doc false
  defp handle_error(conn, reason, opts) do
    the_connection = conn |> assign(:guardian_failure, reason) |> halt

    {mod, meth} = Map.get(opts, :handler)
    apply(
      mod,
      meth,
      [the_connection, Map.merge(the_connection.params, %{reason: reason})]
    )
  end

  defp check_claims(conn, opts = %{claims: claims_to_check}, claims) do
    claims_match = claims_to_check
                   |> Map.keys
                   |> Enum.all?(&(claims_to_check[&1] == claims[&1]))
    if claims_match do
      handle_error(conn, {:error, :claims_match}, opts)
    else
      conn
    end
  end

  defp build_handler_tuple(%{handler: mod}) do
    {mod, :already_authenticated}
  end

  defp build_handler_tuple(_) do
    {Guardian.Plug.ErrorHandler, :already_authenticated}
  end
end
