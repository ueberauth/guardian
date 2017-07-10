if Code.ensure_loaded?(Phoenix) do
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
      def connect(_params, socket) do
        :error
      end
    end
    ```

    If you want more control over the authentication of the connection, then you
    should `import Guardian.Phoenix.Socket` and use the `sign_in` function
    to authenticate.

    ```elixir
    defmodule MyApp.UserSocket do
      use Phoenix.Socket
      import Guardian.Phoenix.Socket

      def connect(%{"guardian_token" => token} = params, socket) do
        case sign_in(socket, MyApp.Guardian, token) do
          {:ok, authed_socket, guardian_params} ->
            {:ok, authed_socket}
          _ -> :error
        end
      end
    end
    ```

    If you want to authenticate on the join of a channel, you can import this
    module and use the sign_in function as normal.
    """

    import Guardian.Plug.Keys

    alias Guardian.Plug, as: GPlug
    alias Phoenix.Socket

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

        def connect(%{unquote(params_key) => token} = params, socket) when not is_nil(token) do
          case sign_in(socket, unquote(module), token, %{}, key: unquote(key)) do
            {:ok, authed_socket, _guardian_params} -> {:ok, authed_socket}
            err -> :error
          end
        end
      end
    end

    @doc """
    Puts the current token onto the socket for later use.

    Get the token from the socket with `current_token`
    """
    @spec put_current_token(
      socket :: Socket.t,
      token :: Guardian.Token.token | nil,
      key :: atom | String.t | nil
    ) :: Socket.t
    def put_current_token(socket, token, key \\ :default) do
      Socket.assign(socket, token_key(key), token)
    end

    @doc """
    Put the current claims onto the socket for later use.
    Get the claims from the socket with `current_claims`
    """
    @spec put_current_claims(
      socket :: Socket.t,
      new_claims :: Guardian.Token.claims | nil,
      atom | String.t | nil
    ) :: Socket.t
    def put_current_claims(socket, new_claims, key \\ :default) do
      Socket.assign(socket, claims_key(key), new_claims)
    end

    @doc """
    Put the current resource onto the socket for later use.
    Get the resource from the socket with `current_resource`
    """
    @spec put_current_resource(
      socket :: Socket.t,
      resource :: Guardian.Token.resource | nil,
      key :: atom | String.t | nil
    ) :: Socket.t
    def put_current_resource(socket, resource, key \\ :default) do
      Socket.assign(socket, resource_key(key), resource)
    end

    @doc """
    Fetches the `claims` map that was encoded into the token from the socket.
    """
    @spec current_claims(Socket.t, atom | String.t) :: Guardian.Token.claims | nil
    def current_claims(socket, key \\ :default) do
      key = claims_key(key)
      socket.assigns[key]
    end

    @doc """
    Fetches the token that was provided for the initial authentication.
    This is provided as an encoded string and fetched from the socket.
    """
    @spec current_token(Socket.t, atom | String.t) :: Guardian.Token.token | nil
    def current_token(socket, key \\ :default) do
      key = token_key(key)
      socket.assigns[key]
    end

    @doc """
    Fetches the resource from that was previously put onto the socket.
    """
    @spec current_resource(Socket.t, atom | String.t) :: Guardian.Token.resource | nil
    def current_resource(socket, key \\ :default) do
      key = resource_key(key)
      socket.assigns[key]
    end

    @doc """
    Boolean if the token is present or not to indicate an authenticated socket
    """
    @spec authenticated?(Socket.t, atom | String.t) :: true | false
    def authenticated?(socket, key \\ :default) do
      current_token(socket, key) != nil
    end

    @doc """
    Assigns the resource, token and claims to the socket.

    Use the `key` to specifiy a different location. This allows
    multiple tokens to be active on a socket at once.
    """

    @spec assign_rtc(
      socket :: Socket.t,
      resource :: Guardian.Token.resource | nil,
      token :: Guardian.Token.token | nil,
      claims :: Guardian.Token.claims | nil,
      key :: atom | String.t | nil
    ) :: Socket.t
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
    @spec sign_in(
      socket :: Socket.t,
      impl :: module,
      token :: Guardian.Token.token | nil,
      claims_to_check :: Guardian.Token.claims,
      opts :: Guardian.opts
    ) :: {:ok, Socket.t, %{claims: Guardian.Token.claims, token: Guardian.Token.token, resource: any}} |
         {:error, atom | any}
    def sign_in(socket, impl, token, claims_to_check \\ %{}, opts \\ [])

    def sign_in(_socket, _impl, nil, _claims_to_check, _opts), do: {:error, :no_token}

    def sign_in(socket, impl, token, claims_to_check, opts) do
      with {:ok, resource, claims} <- Guardian.resource_from_token(impl, token, claims_to_check, opts),
           key <- Keyword.get(opts, :key, GPlug.default_key()) do

        authed_socket = assign_rtc(socket, resource, token, claims, key)

        {:ok, authed_socket, %{claims: claims, token: token, resource: resource}}
      end
    end

    @doc """
    Signout of the socket and also revoke the token. Using with GuardianDB this
    will render the token useless for future requests.
    """
    @spec sign_out!(Socket.t, module, atom | String.t | nil) :: Socket.t
    def sign_out!(socket, impl, key \\ :default) do
      token = current_token(socket, key)
      if token, do: Guardian.revoke(impl, token, [])
      sign_out(socket, key)
    end

    @doc """
    Sign out of the socket but do not revoke. The token will still be valid for
    future requests.
    """
    @spec sign_out(Socket.t, atom | String.t | nil) :: Socket.t
    def sign_out(socket, key \\ :default) do
      assign_rtc(socket, nil, nil, nil, key)
    end
  end
end
