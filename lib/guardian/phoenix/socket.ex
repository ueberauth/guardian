if Code.ensure_loaded?(Phoenix) do
  defmodule Guardian.Phoenix.Socket do
    @moduledoc """
    Provides functions for managing authentication with sockets.

    This module mostly provides convenience functions for storing tokens, claims and resources
    on the socket assigns.

    The main functions you'll be interested in are:

    * `Guardian.Phoenix.Socket.authenticated?` - check if the socket has been authenticated
    * `Guardian.Phoenix.Socket.authenticate` - Sign in a resource to a socket. Similar to `Guardian.Plug.authenticate`

    ### Getters

    Once you're authenticated with your socket, you can use the getters
    to fetch information about the authenticated resource for the socket.

    * `Guardian.Phoenix.Socket.current_claims`
    * `Guardian.Phoenix.Socket.current_token`
    * `Guardian.Phoenix.Socket.current_resource`

    These are the usual functions you'll want to use when dealing with authentication on sockets.

    There is a bit of a difference between the usual `Guardian.Plug.sign_in` and the socket one.
    The socket authenticate receives a token and signs in from that.
    Please note that this is mere sugar on the underlying Guardian functions.

    As an example:
    ```elixir
    defmodule MyApp.UserSocket do
      use Phoenix.Socket

      def connect(%{"token" => token}, socket) do
        case Guardian.Phoenix.Socket.authenticate(socket, MyApp.Guardian, token) do
          {:ok, authed_socket} ->
            {:ok, authed_socket}
          {:error, _} -> :error
        end
      end

      # This function will be called when there was no authentication information
      def connect(_params, socket) do
        :error
      end
    end
    ```

    If you want to authenticate on the join of a channel, you can import this
    module and use the authenticate function as normal.
    """

    import Guardian.Plug.Keys

    alias Phoenix.Socket

    @doc """
    Puts the current token onto the socket for later use.

    Get the token from the socket with `current_token`
    """
    @spec put_current_token(
            socket :: Socket.t(),
            token :: Guardian.Token.token() | nil,
            key :: atom | String.t() | nil
          ) :: Socket.t()
    def put_current_token(socket, token, key \\ :default) do
      Socket.assign(socket, token_key(key), token)
    end

    @doc """
    Put the current claims onto the socket for later use.
    Get the claims from the socket with `current_claims`
    """
    @spec put_current_claims(
            socket :: Socket.t(),
            new_claims :: Guardian.Token.claims() | nil,
            atom | String.t() | nil
          ) :: Socket.t()
    def put_current_claims(socket, new_claims, key \\ :default) do
      Socket.assign(socket, claims_key(key), new_claims)
    end

    @doc """
    Put the current resource onto the socket for later use.
    Get the resource from the socket with `current_resource`
    """
    @spec put_current_resource(
            socket :: Socket.t(),
            resource :: Guardian.Token.resource() | nil,
            key :: atom | String.t() | nil
          ) :: Socket.t()
    def put_current_resource(socket, resource, key \\ :default) do
      Socket.assign(socket, resource_key(key), resource)
    end

    @doc """
    Fetches the `claims` map that was encoded into the token from the socket.
    """
    @spec current_claims(Socket.t(), atom | String.t()) :: Guardian.Token.claims() | nil
    def current_claims(socket, key \\ :default) do
      key = claims_key(key)
      socket.assigns[key]
    end

    @doc """
    Fetches the token that was provided for the initial authentication.
    This is provided as an encoded string and fetched from the socket.
    """
    @spec current_token(Socket.t(), atom | String.t()) :: Guardian.Token.token() | nil
    def current_token(socket, key \\ :default) do
      key = token_key(key)
      socket.assigns[key]
    end

    @doc """
    Fetches the resource from that was previously put onto the socket.
    """
    @spec current_resource(Socket.t(), atom | String.t()) :: Guardian.Token.resource() | nil
    def current_resource(socket, key \\ :default) do
      key = resource_key(key)
      socket.assigns[key]
    end

    @doc """
    Boolean if the token is present or not to indicate an authenticated socket
    """
    @spec authenticated?(Socket.t(), atom | String.t()) :: true | false
    def authenticated?(socket, key \\ :default) do
      current_token(socket, key) != nil
    end

    @doc """
    Assigns the resource, token and claims to the socket.

    Use the `key` to specify a different location. This allows
    multiple tokens to be active on a socket at once.
    """

    @spec assign_rtc(
            socket :: Socket.t(),
            resource :: Guardian.Token.resource() | nil,
            token :: Guardian.Token.token() | nil,
            claims :: Guardian.Token.claims() | nil,
            key :: atom | String.t() | nil
          ) :: Socket.t()
    def assign_rtc(socket, resource, token, claims, key \\ :default) do
      socket
      |> put_current_token(token, key)
      |> put_current_claims(claims, key)
      |> put_current_resource(resource, key)
    end

    @doc """
    Given an implementation module and token, this will

    * decode and verify the token
    * load the resource
    * store the resource, claims and token on the socket.

    Use the `key` to store the information in a different location.
    This allows multiple tokens and resources on a single socket.
    """
    @spec authenticate(
            socket :: Socket.t(),
            impl :: module,
            token :: Guardian.Token.token() | nil,
            claims_to_check :: Guardian.Token.claims(),
            opts :: Guardian.options()
          ) :: {:ok, Socket.t()} | {:error, atom | any}
    def authenticate(socket, impl, token, claims_to_check \\ %{}, opts \\ [])

    def authenticate(_socket, _impl, nil, _claims_to_check, _opts), do: {:error, :no_token}

    def authenticate(socket, impl, token, claims_to_check, opts) do
      with {:ok, resource, claims} <-
             Guardian.resource_from_token(impl, token, claims_to_check, opts),
           key <- Keyword.get(opts, :key, Guardian.Plug.default_key()) do
        authed_socket = assign_rtc(socket, resource, token, claims, key)

        {:ok, authed_socket}
      end
    end
  end
end
