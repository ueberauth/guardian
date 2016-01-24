defmodule Guardian.Phoenix.Socket do
  @moduledoc """
  Provides functions for managing authentication with sockets.
  Usually you'd use this on the Socket to authenticate on connection on the `connect` function.

  There are two main ways to use this module.

  1. use Guardian.Phoenix.Socket
  2. import Guardian.Phoenix.Socket

  You use this function when you want to automatically sign in a socket on `connect`.
  The case where authentication information is not provided is not handled so that you can handle it yourself.

  ```elixir
  defmodule MyApp.UserSocket do
    use Phoenix.Socket
    use Guardian.Phoenix.Socket

    # This function will be called when there was no authentication information
    def connect(_params,socket) do
      :error
    end
  end
  ```

  If you want more control over the authentication of the connection, then you shoule `import Guardian.Phoenix.Socket` and use the `sign_in` function to authenticate.

  defmodule MyApp.UserSocket do
    use Phoenix.Socket
    import Guardian.Phoenix.Socket

    def connect(%{"guardian_token" => jwt } = params, socket) do
      case sign_in(socket, jwt) do
        {:ok, authed_socket, guardian_params} ->
          {:ok, authed_socket}
        _ -> :error
      end
    end
  end

  If you want to authenticate on the join of a channel, you can import this module and use the sign_in function as normal.
  """
  defmacro __using__(opts) do
    opts = Enum.into(opts, %{})
    key = Map.get(opts, :key, :default)

    quote do
      import Guardian.Phoenix.Socket

      def connect(%{ "guardian_token" => jwt } = params, socket) do
        case sign_in(socket, jwt, params, key: unquote(key)) do
          {:ok, authed_socket, _guardian_params} -> {:ok, authed_socket}
          _ -> :error
        end
      end
    end
  end

  def claims(socket, key \\ :default), do: current_claims(socket, key) # deprecated in 1.0

  @doc """
  Fetches the `claims` map that was encoded into the token.
  """
  def current_claims(socket, key \\ :default), do: socket.assigns[Guardian.Keys.claims_key(key)]

  @doc """
  Fetches the JWT that was provided for the initial authentication. This is provided as an encoded string.
  """
  def current_token(socket, key \\ :default), do: socket.assigns[Guardian.Keys.jwt_key(key)]

  @doc """
  Loads the resource from the serializer.
  The resource is not cached onto the socket so using this function will load a fresh version of the resource each time it's called.
  """
  def current_resource(socket, key \\ :default) do
    case current_claims(socket, key) do
      nil -> nil
      claims ->
        case Guardian.serializer.from_token(claims["sub"]) do
          {:ok, resource} -> resource
          _ -> nil
        end
    end
  end

  @doc """
  Boolean if the token is present or not to indicate an authenticated socket
  """
  def authenticated?(socket, key \\ :default) do
    socket
    |> current_token(key)
    |> is_binary
  end

  def sign_in(_socket, nil), do: {:error, :no_token}
  def sign_in(socket, jwt), do: sign_in(socket, jwt, %{})

  @doc """
  Sign into a socket. Takes a JWT and verifies it. If successful it caches the JWT and decoded claims onto the socket for future use.
  """
  def sign_in(socket, jwt, params, opts \\ []) do
    key = Keyword.get(opts, :key, :default)

    case Guardian.decode_and_verify(jwt, params) do
      {:ok, claims} ->
        case Guardian.serializer.from_token(Map.get(claims, "sub")) do
          {:ok, resource} ->
            authed_socket = socket
            |> Phoenix.Socket.assign(Guardian.Keys.claims_key(key), claims)
            |> Phoenix.Socket.assign(Guardian.Keys.jwt_key(key), jwt)
            {:ok, authed_socket, %{claims: claims, resource: resource, jwt: jwt}}
          error -> error
        end
      error -> error
    end
  end

  @doc """
  Signout of the socket and also revoke the token. Using with GuardianDB this will render the token useless for future requests.
  """
  def sign_out!(socket, key \\ :default) do
    jwt = current_token(socket)
    claims = current_claims(socket)
    Guardian.revoke!(jwt, claims)
    sign_out(socket, key)
  end

  @doc """
  Sign out of the socket but do not revoke. The token will still be valid for future requests.
  """
  def sign_out(socket, key \\ :default) do
    socket
    |> Phoenix.Socket.assign(Guardian.Keys.claims_key(key), nil)
    |> Phoenix.Socket.assign(Guardian.Keys.resource_key(key), nil)
    |> Phoenix.Socket.assign(Guardian.Keys.jwt_key(key), nil)
  end
end
