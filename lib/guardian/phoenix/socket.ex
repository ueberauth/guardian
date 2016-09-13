defmodule Guardian.Phoenix.Socket do
  @moduledoc """
  Provides functions for managing authentication with sockets.
  Usually you'd use this on the Socket to authenticate on connection on
  the `connect` function.

  There are two main ways to use this module.

  1. use Guardian.Phoenix.Socket
  2. import Guardian.Phoenix.Socket

  You use this function when you want to automatically sign in a socket
  on `connect`. The case where authentication information is not provided
  is not handled so that you can handle it yourself.

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

  If you want more control over the authentication of the connection, then you
  should `import Guardian.Phoenix.Socket` and use the `sign_in` function
  to authenticate.

  defmodule MyApp.UserSocket do
    use Phoenix.Socket
    import Guardian.Phoenix.Socket

    def connect(%{"guardian_token" => jwt} = params, socket) do
      case sign_in(socket, jwt) do
        {:ok, authed_socket, guardian_params} ->
          {:ok, authed_socket}
        _ -> :error
      end
    end
  end

  If you want to authenticate on the join of a channel, you can import this
  module and use the sign_in function as normal.
  """
  defmacro __using__(opts) do
    opts = Enum.into(opts, %{})
    key = Map.get(opts, :key, :default)

    quote do
      import Guardian.Phoenix.Socket

      def connect(%{"guardian_token" => jwt} = params, socket) do
        case sign_in(socket, jwt, params, key: unquote(key)) do
          {:ok, authed_socket, _guardian_params} -> {:ok, authed_socket}
          _ -> :error
        end
      end
    end
  end

  @doc """
  Set the current token. Used internally and in tests. Not expected to be
  used inside channels or sockets.
  """
  def set_current_token(socket, jwt, key \\ :default) do
    Phoenix.Socket.assign(socket, Guardian.Keys.jwt_key(key), jwt)
  end

  @doc """
  Set the current claims. Used internally and in tests. Not expected to be
  used inside channels or sockets.
  """
  def set_current_claims(socket, new_claims, key \\ :default) do
    Phoenix.Socket.assign(socket, Guardian.Keys.claims_key(key), new_claims)
  end

  @doc """
  Set the current resource. Used internally and in tests. Not expected to be
  used inside channels or sockets.
  """
  def set_current_resource(socket, resource, key \\ :default) do
    Phoenix.Socket.assign(socket, Guardian.Keys.resource_key(key), resource)
  end

  # deprecated in 1.0
  def claims(socket, key \\ :default), do: current_claims(socket, key)

  @doc """
  Fetches the `claims` map that was encoded into the token.
  """
  def current_claims(socket, key \\ :default) do
    socket.assigns[Guardian.Keys.claims_key(key)]
  end

  @doc """
  Fetches the JWT that was provided for the initial authentication.
  This is provided as an encoded string.
  """
  def current_token(socket, key \\ :default) do
    socket.assigns[Guardian.Keys.jwt_key(key)]
  end

  @doc """
  Loads the resource from the serializer.
  The resource is not cached onto the socket so using this function will load a
  fresh version of the resource each time it's called.
  """
  def current_resource(socket, key \\ :default) do
    case current_claims(socket, key) do
      nil -> nil
      the_claims ->
        case Guardian.serializer.from_token(the_claims["sub"]) do
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
  Sign into a socket. Takes a JWT and verifies it. If successful it caches the
  JWT and decoded claims onto the socket for future use.
  """
  def sign_in(socket, jwt, params, opts \\ []) do
    key = Keyword.get(opts, :key, :default)

    case Guardian.decode_and_verify(jwt, params) do
      {:ok, decoded_claims} ->
        case Guardian.serializer.from_token(Map.get(decoded_claims, "sub")) do
          {:ok, res} ->
            authed_socket = socket
            |> set_current_claims(decoded_claims, key)
            |> set_current_token(jwt, key)
            {
              :ok,
              authed_socket,
              %{
                claims: decoded_claims,
                resource: res,
                jwt: jwt
              }
          }
          error -> error
        end
      error -> error
    end
  end

  @doc """
  Signout of the socket and also revoke the token. Using with GuardianDB this
  will render the token useless for future requests.
  """
  def sign_out!(socket, key \\ :default) do
    jwt = current_token(socket)
    the_claims = current_claims(socket)
    _ = Guardian.revoke!(jwt, the_claims)
    sign_out(socket, key)
  end

  @doc """
  Sign out of the socket but do not revoke. The token will still be valid for
  future requests.
  """
  def sign_out(socket, key \\ :default) do
    socket
    |> set_current_claims(nil, key)
    |> set_current_token(nil, key)
    |> set_current_resource(nil, key)
  end
end
