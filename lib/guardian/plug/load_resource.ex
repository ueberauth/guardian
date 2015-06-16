defmodule Guardian.Plug.LoadResource do
  def init(opts), do: opts

  def call(conn, opts) do
    key = Dict.get(opts, :key, :default)

    case Guardian.Plug.current_resource(conn, key) do
      { :ok, resource } -> conn
      { :error, reason } -> conn
      _ ->
        case Guardian.Plug.claims(conn, key) do
          { :ok, claims } ->
            case Guardian.serializer.from_token(Dict.get(claims, :sub)) do
              { :ok, resource } -> Guardian.Plug.set_current_resource(conn, resource, key)
              { :error, reason } -> Guardian.Plug.set_current_resource(conn, nil, key)
            end
          { :error, reason } -> Guardian.Plug.set_current_resource(conn, nil, key)
          _ -> Guardian.Plug.set_current_resource(conn, nil, key)
        end
    end
  end
end
