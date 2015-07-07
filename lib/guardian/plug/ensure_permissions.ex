defmodule Guardian.Plug.EnsurePermissions do
  @moduledoc """
  Use this plug to ensure that there are the correct permissions set in the claims found on the connection.

  ### Example

      plug Guardian.Plug.EnsurePermissions, admin: [:read, :write], on_failure: { SomeMod, :some_func } # read and write permissions for the admin set
      plug Guardian.Plug.EnsurePermissions, admin: [:read, :write], default: [:profile], on_failure: { SomeMod, :some_func } # read AND write permissions for the admin set AND :profile for the default set

      plug Guardian.Plug.EnsurePermissions, key: :secret, admin: [:read, :write], on_failure: { SomeMod, :some_func } # admin :read AND :write for the claims located in the :secret location

  On failure will be handed the connection with the conn, and params where reason: :forbidden
  """
  def init(opts) do
    opts = Enum.into(opts, %{})
    on_failure = Dict.get(opts, :on_failure)
    key = Dict.get(opts, :key, :default)
    perms = Dict.delete(opts, :on_failure) |> Dict.delete(:key)

    case on_failure do
      { _mod, _meth } ->
        %{
          on_failure: on_failure,
          key: key,
          perm_keys: Dict.keys(perms),
          perms: perms,
        }
      _ -> raise "Requires an on_failure function { Mod, :function_name }"
    end
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
    { mod, meth } = Dict.get(opts, :on_failure)
    apply(mod, meth, [conn, Dict.merge(conn.params, %{ reason: :forbidden })])
  end
end
