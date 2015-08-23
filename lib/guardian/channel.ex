defmodule Guardian.Channel do
  @moduledoc """
  Provides integration for channels to use Guardian tokens.

  ## Example

      defmodule MyApp.MyChannel do
        use Phoenix.Channel
        use Guardian.Channel

        def join(_room, %{ claims: claims, resource: resource }, socket) do
          { :ok, %{ message: "Joined" }, socket }
        end

        def join(room, _, socket) do
          { :error,  :authentication_required }
        end

        def handle_in("ping", _payload, socket) do
          user = Guardian.Channel.current_resource(socket)
          broadcast socket, "pong", %{ message: "pong", from: user.email }
          { :noreply, socket }
        end
      end

  Tokens will be parsed and the claims and resource assigned to the socket.

  ## Example

      let socket = new Socket("/ws");
      socket.connect();

      let guardianToken = jQuery('meta[name="guardian_token"]').attr('content');

      let chan = socket.chan("pings", { guardian_token: guardianToken });
  """
  defmacro __using__(opts) do
    opts = Enum.into(opts, %{})
    key = Dict.get(opts, :key, :default)

    quote do
      def join(room, auth = %{ "guardian_token" => jwt }, socket) do
        handle_guardian_join(room, jwt, %{ }, socket)
      end

      def handle_guardian_auth_failure(reason), do: { :error, %{ error: reason } }

      defp handle_guardian_join(room, jwt, params, socket) do
        case Guardian.verify(jwt, params) do
          { :ok, claims } ->
            case Guardian.serializer.from_token(Dict.get(claims, "sub")) do
              { :ok, resource } ->
                authed_socket = socket
                |> assign(Guardian.Keys.claims_key(unquote(key)), claims)
                |> assign(Guardian.Keys.resource_key(unquote(key)), resource)
                join(room, %{ claims: claims, resource: resource }, authed_socket)
              { :error, reason } -> handle_guardian_auth_failure(reason)
            end
          { :error, reason } -> handle_guardian_auth_failure(reason)
        end
      end

      defoverridable [handle_guardian_auth_failure: 1]
    end
  end

  def claims(socket, key \\ :default), do: socket.assigns[Guardian.Keys.claims_key(key)]
  def current_resource(socket, key \\ :default), do: socket.assigns[Guardian.Keys.resource_key(key)]
end
