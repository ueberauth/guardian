defmodule Guardian.Plug.EnsurePermissions do
  @moduledoc """
  Use this plug to ensure that there are the
  correct permissions set in the claims found on the connection.

  ### Example

      alias Guardian.Plug.EnsurePermissions

      # read and write permissions for the admin set
      plug EnsurePermissions, admin: [:read, :write], handler: SomeMod,

      # read AND write permissions for the admin set
      # AND :profile for the default set
      plug EnsurePermissions, admin: [:read, :write],
                              default: [:profile],
                              handler: SomeMod

      # admin :read AND :write for the claims located in the :secret location
      plug EnsurePermissions, key: :secret,
                              admin: [:read, :write],
                              handler:SomeMod

  On failure will be handed the connection with the conn,
  and params where reason: `:forbidden`

  The handler will be called on failure.
  The `:unauthorized` function will be called when a failure is detected.
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
        _ -> raise "Requires a handler module to be passed"
      end
    end

    %{
      handler: handler,
      key: key,
      perm_keys: Map.keys(perms),
      perms: perms,
    }
  end

  @doc false
  def call(conn, opts) do
    key = Map.get(opts, :key)
    case Guardian.Plug.claims(conn, key) do
      {:ok, claims} ->
        perms = Map.get(opts, :perms, %{})
        result = Enum.all?(Map.get(opts, :perm_keys), fn(perm_key) ->
          found_perms = Guardian.Permissions.from_claims(claims, perm_key)
          Guardian.Permissions.all?(
            found_perms,
            Map.get(perms, perm_key),
            perm_key
          )
        end)
        if result, do: conn, else: handle_error(conn, opts)
      {:error, _} -> handle_error(conn, opts)
    end
  end

  defp handle_error(conn, opts) do
    the_connection = conn |> assign(:guardian_failure, :forbidden) |> halt

    {mod, meth} = Map.get(opts, :handler)
    apply(
      mod,
      meth,
      [
        the_connection,
        Map.merge(the_connection.params, %{reason: :forbidden})
      ]
    )
  end
end
