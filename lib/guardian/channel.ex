defmodule Guardian.Channel do
  defmacro __using__(opts) do
    quote do
      def join(room, auth = %{ "guardian_token" => jwt, "csrf_token" => csrf_token }, socket) do
        Guardian.Channel.handle_join(__MODULE__, room, jwt, %{ csrf: csrf_token }, socket, unquote(opts))
      end

      def join(room, auth = %{ "guardian_token" => jwt }, socket) do
        Guardian.Channel.handle_join(__MODULE__, room, jwt, %{ }, socket, unquote(opts))
      end
    end
  end

  def handle_error(reason, opts) do
    case Dict.get(opts, :on_failure) do
      { mod, method } -> apply(mod, method, [reason])
      _ -> { :error, %{ reason: reason } }
    end
  end

  def handle_join(mod, room, jwt, params, socket, opts) do
    key = Dict.get(opts, :key, :default)
    case Guardian.verify(jwt, params) do
      { :ok, claims } ->
        case Guardian.serializer.from_token(Dict.get(claims, :sub)) do
          { :ok, resource } ->
            authed_socket = socket
            |> Phoenix.Channel.assign(Guardian.Keys.claims_key(key), claims)
            |> Phoenix.Channel.assign(Guardian.Keys.resource_key(key), resource)
            apply(mod, :join, [room, %{ guardian: claims }, authed_socket])
          { :error, reason } -> handle_error(reason, opts)
        end
      { :error, reason } -> handle_error(reason, opts)
    end
  end

  def claims(socket, key \\ :default), do: socket.assigns[Guardian.Keys.claims_key(key)]
  def current_resource(socket, key \\ :default), do: socket.assigns[Guardian.Keys.resource_key(key)]
end
