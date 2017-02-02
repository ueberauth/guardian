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

      # read AND write permissions for the admin set
      # OR :profile for the default set
      plug EnsurePermissions, one_of: [%{admin: [:read, :write]},
                              %{default: [:profile]}],
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

    perm_sets = case Map.get(opts, :one_of) do
      nil ->
        single_set = Map.drop(opts, [:handler, :on_failure, :key, :one_of])
        if Enum.empty?(single_set) do
          []
        else
          [single_set]
        end
      one_of ->
        if Keyword.keyword?(one_of) do
          [Enum.into(one_of, %{})]
        else
          one_of
        end
    end

    handler_tuple = if handler do
      {handler, :unauthorized}
    else
      case on_failure do
        {mod, f} ->
          _ = Logger.warn(":on_failure is deprecated. Use :handler")
          {mod, f}
        _ -> raise "Requires a handler module to be passed"
      end
    end

    %{
      handler: handler_tuple,
      key: key,
      perm_sets: perm_sets
    }
  end

  @doc false
  def call(conn, opts) do
    key = Map.get(opts, :key)
    case Guardian.Plug.claims(conn, key) do
      {:ok, claims} ->
        if matches_permissions?(claims, Map.get(opts, :perm_sets)) do
          conn
        else
          handle_error(conn, opts)
        end
      {:error, _} -> handle_error(conn, opts)
    end
  end

  defp matches_permissions?(_, []), do: true
  defp matches_permissions?(claims, sets) do
    Enum.any?(sets, &matches_permission_set?(claims, &1))
  end

  defp matches_permission_set?(claims, set) do
    Enum.all?(set, fn({perm_key, required_perms}) ->
      claims
      |> Guardian.Permissions.from_claims(perm_key)
      |> Guardian.Permissions.all?(required_perms, perm_key)
    end)
  end

  defp handle_error(%Plug.Conn{params: params} = conn, opts) do
    conn = conn |> assign(:guardian_failure, :forbidden) |> halt
    params = Map.merge(params, %{reason: :forbidden})

    {mod, meth} = Map.get(opts, :handler)

    apply(mod, meth, [conn, params])
  end
end
