defmodule Guardian.Channel do
  @moduledoc """
  Provides integration for channels to use Guardian tokens.

  ## Example

      defmodule MyApp.MyChannel do
        use Phoenix.Channel
        use Guardian.Channel

        def join(_room, %{ claims: claims, resource: resource }, socket) do
          {:ok, %{ message: "Joined" }, socket}
        end

        def join(room, _, socket) do
          {:error,  :authentication_required}
        end

        def handle_in("ping", _payload, socket) do
          user = current_resource(socket)
          broadcast(socket, "pong", %{message: "pong", from: user.email})
          {:noreply, socket}
        end
      end

  Tokens will be parsed and the claims and resource assigned to the socket.

  ## Example

      let socket = new Socket("/ws")
      socket.connect()

      let guardianToken = jQuery('meta[name="guardian_token"]').attr('content')
      let chan = socket.chan("pings", { guardian_token: guardianToken })

  Consider using Guardian.Phoenix.Socket helpers
  directly and authenticating the connection rather than the channel.
  """
  defmacro __using__(opts) do
    key = Keyword.get(opts, :key, :default)

    quote do
      import Guardian.Phoenix.Socket

      def join(room, params = %{"guardian_token" => jwt}, socket) do
        case sign_in(socket, jwt, params, key: unquote(key)) do
          {:ok, authed_socket, guardian_params} ->
            join_params = params
            |> Map.drop(["guardian_token"])
            |> Map.merge(guardian_params)

            __MODULE__.join(room, join_params, authed_socket)
          {:error, reason} -> handle_guardian_auth_failure(reason)
        end
      end

      def handle_guardian_auth_failure(reason), do: {:error, %{error: reason}}

      defoverridable [handle_guardian_auth_failure: 1]
    end
  end
end
