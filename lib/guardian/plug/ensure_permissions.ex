defmodule Guardian.Plug.EnsurePermissions do
  @moduledoc """
  Use this plug to ensure that there are the correct permissions set in the claims found on the connection.

  ### Example

      plug Guardian.Plug.EnsurePermissions, admin: [:read, :write], handler: SomeMod, # read and write permissions for the admin set
      plug Guardian.Plug.EnsurePermissions, admin: [:read, :write], default: [:profile], handler: SomeMod # read AND write permissions for the admin set AND :profile for the default set

      plug Guardian.Plug.EnsurePermissions, key: :secret, admin: [:read, :write], handler:SomeMod, # admin :read AND :write for the claims located in the :secret location

  On failure will be handed the connection with the conn, and params where reason: :forbidden

  The handler will be called on failure. You may specify the handler inline as
  in the above example or in the global configuration.
  The `:unauthorized` function will be called when a failure is detected.

  ```elixir
  config :guardian, Guardian,
    handler: MyHandler
    # …
  """

  require Logger
  import Plug.Conn

  def init(opts) do
    opts = Enum.into(opts, %{})
    on_failure = Map.get(opts, :on_failure)
    key = Map.get(opts, :key, :default)
    handler = Map.get(opts, :handler)
    perms = Map.drop(opts, [:handler, :on_failure, :key])

    if handler do
      handler = {handler, :unauthorized}
    else
      handler = case on_failure do
        {mod, f} ->
          Logger.log(:warn, "on_failure is deprecated. Use handler")
          {mod, f}
        _ -> {Guardian.config(:handler, Guardian.Plug.ErrorHandler), :unauthorized}
      end
    end

    %{
      handler: handler,
      key: key,
      perm_keys: Dict.keys(perms),
      perms: perms,
    }
  end

  @doc false
  def call(conn, opts) do
    key = Dict.get(opts, :key)
    case Guardian.Plug.claims(conn, key) do
      { :ok, claims } ->
        perms = Dict.get(opts, :perms, %{})
        result = Enum.all?(Dict.get(opts, :perm_keys), fn(perm_key) ->
          found_perms = Guardian.Permissions.from_claims(claims, perm_key)
          Guardian.Permissions.all?(found_perms, Dict.get(perms, perm_key), perm_key)
        end)
        if result, do: conn, else: handle_error(conn, opts)
      { :error, _ } -> handle_error(conn, opts)
    end
  end

  defp handle_error(conn, opts) do
    the_connection = conn |> assign(:guardian_failure, :forbidden) |> halt

    { mod, meth } = Map.get(opts, :handler)
    apply(mod, meth, [the_connection, Map.merge(the_connection.params, %{ reason: :forbidden })])
  end
end
