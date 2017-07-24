if Code.ensure_loaded?(Phoenix) do
  defmodule Guardian.Phoenix.Channel do
    @moduledoc """
    Provides integration for channels to use Guardian tokens.

    ## Example

        defmodule MyApp.MyChannel do
          use Phoenix.Channel
          use Guardian.Phoenix.Channel

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
      mod = Keyword.get(opts, :module)
      module =
        case mod do
          {:__aliases__, _, _} = stuff -> Macro.expand(stuff, __ENV__)
          mod -> mod
        end

      params_key =
        if Keyword.get(opts, :token_key) do
          opts |> Keyword.get(:token_key) |> to_string()
        else
          module |> apply(:config, [:socket_token_key, "guardian_token"]) |> to_string()
        end

      quote do
        import Guardian.Phoenix.Socket

        def join(room, %{unquote(params_key) => token} = params, socket) do
          existing_resource = current_resource(socket, unquote(key))
          existing_claims = current_claims(socket, unquote(key))
          existing_token = current_token(socket, unquote(key))

          if existing_resource do
            params =
              params
              |> Map.put(:claims, existing_claims)
              |> Map.put(:resource, existing_resource)
              |> Map.put(:token, existing_token)

            __MODULE__.join(room, params, socket)
          else
            params = Map.drop(params, [unquote(params_key)])
            case sign_in(socket, unquote(module), token, params, key: unquote(key)) do
              {:ok, authed_socket, guardian_params} ->
                join_params =
                  params
                  |> Map.drop([unquote(params_key)])
                  |> Map.merge(guardian_params)

                __MODULE__.join(room, join_params, authed_socket)
              {:error, reason} -> handle_guardian_auth_failure(reason)
            end
          end
        end

        def handle_guardian_auth_failure(reason), do: {:error, %{error: reason}}

        defoverridable [handle_guardian_auth_failure: 1]
      end
    end
  end
end
