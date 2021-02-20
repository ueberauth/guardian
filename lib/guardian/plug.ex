if Code.ensure_loaded?(Plug) do
  defmodule Guardian.Plug do
    @moduledoc ~S"""
    Provides functions for the implementation module for dealing with
    Guardian in a Plug environment.

    ```elixir
    defmodule MyApp.Tokens do
      use Guardian, otp_app: :my_app

      # ... snip
    end
    ```

    Your implementation module will be given a `Plug` module for
    interacting with plug.

    If you're using Guardian in your application most of the setters will
    be uninteresting. They're mostly for library authors and Guardian itself.

    The usual functions you'd use in your application are:

    ### `sign_in(conn, resource, claims \\ %{}, opts \\ [])`

    Sign in a resource for your application.
    This will generate a token for your resource according to
    your TokenModule and `subject_for_token` callback.

    `sign_in` will also cache the `resource`, `claims`, and `token` on the
    connection.

    ```elixir
    conn = MyApp.Guardian.Plug.sign_in(conn, resource, my_custom_claims)
    ```

    If there is a session present the token will be stored in the session
    to provide traditional session based authentication.
    """

    defmodule UnauthenticatedError do
      defexception message: "Unauthenticated", status: 401
    end

    @default_key "default"
    @default_cookie_max_age [max_age: 60 * 60 * 24 * 7 * 4]

    import Guardian, only: [returning_tuple: 1]
    import Guardian.Plug.Keys
    import Plug.Conn

    alias Guardian.Plug.Pipeline

    alias __MODULE__.UnauthenticatedError

    defmacro __using__(impl) do
      quote do
        @spec implementation() :: unquote(impl)
        def implementation, do: unquote(impl)

        def put_current_token(conn, token, opts \\ []),
          do: Guardian.Plug.put_current_token(conn, token, opts)

        def put_current_claims(conn, claims, opts \\ []),
          do: Guardian.Plug.put_current_claims(conn, claims, opts)

        def put_current_resource(conn, resource, opts \\ []),
          do: Guardian.Plug.put_current_resource(conn, resource, opts)

        def put_session_token(conn, token, opts \\ []),
          do: Guardian.Plug.put_session_token(conn, token, opts)

        def current_token(conn, opts \\ []), do: Guardian.Plug.current_token(conn, opts)

        def current_claims(conn, opts \\ []), do: Guardian.Plug.current_claims(conn, opts)

        def current_resource(conn, opts \\ []), do: Guardian.Plug.current_resource(conn, opts)

        def authenticated?(conn, opts \\ []), do: Guardian.Plug.authenticated?(conn, opts)

        def sign_in(conn, resource, claims \\ %{}, opts \\ []),
          do: Guardian.Plug.sign_in(conn, implementation(), resource, claims, opts)

        def sign_out(conn, opts \\ []), do: Guardian.Plug.sign_out(conn, implementation(), opts)

        def remember_me(conn, resource, claims \\ %{}, opts \\ []),
          do: Guardian.Plug.remember_me(conn, implementation(), resource, claims, opts)

        @spec remember_me_from_token(
                Plug.Conn.t(),
                Guardian.Token.token(),
                Guardian.Token.claims(),
                Guardian.options()
              ) :: Plug.Conn.t()
        def remember_me_from_token(conn, token, claims \\ %{}, opts \\ []),
          do: Guardian.Plug.remember_me_from_token(conn, implementation(), token, claims, opts)

        def clear_remember_me(conn, opts \\ []),
          do: Guardian.Plug.clear_remember_me(conn, implementation(), opts)
      end
    end

    def session_active?(conn) do
      key = :second |> System.os_time() |> to_string()
      get_session(conn, key) == nil
    rescue
      ArgumentError -> false
    end

    @spec authenticated?(Plug.Conn.t(), Guardian.options()) :: true | false
    def authenticated?(conn, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> token_key()

      conn.private[key] != nil
    end

    @doc """
    Provides the default key for the location of a token in the session and
    connection.
    """

    @spec default_key() :: String.t()
    def default_key, do: @default_key

    @spec current_claims(Plug.Conn.t(), Guardian.options()) :: Guardian.Token.claims() | nil
    def current_claims(conn, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> claims_key()

      conn.private[key]
    end

    @spec current_resource(Plug.Conn.t(), Guardian.options()) :: any | nil
    def current_resource(conn, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> resource_key()

      conn.private[key]
    end

    @spec current_token(Plug.Conn.t(), Guardian.options()) :: Guardian.Token.token() | nil
    def current_token(conn, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> token_key()

      conn.private[key]
    end

    @spec put_current_token(Plug.Conn.t(), Guardian.Token.token() | nil, Guardian.options()) :: Plug.Conn.t()
    def put_current_token(conn, token, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> token_key()

      put_private(conn, key, token)
    end

    @spec put_current_claims(Plug.Conn.t(), Guardian.Token.claims() | nil, Guardian.options()) :: Plug.Conn.t()
    def put_current_claims(conn, claims, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> claims_key()

      put_private(conn, key, claims)
    end

    @spec put_current_resource(Plug.Conn.t(), resource :: any | nil, Guardian.options()) :: Plug.Conn.t()
    def put_current_resource(conn, resource, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> resource_key()

      put_private(conn, key, resource)
    end

    @spec put_session_token(
            Plug.Conn.t(),
            Guardian.Token.token(),
            Guardian.options()
          ) :: Plug.Conn.t()
    def put_session_token(conn, token, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> token_key()

      conn
      |> put_session(key, token)
      |> configure_session(renew: true)
    end

    @spec sign_in(Plug.Conn.t(), module, any, Guardian.Token.claims(), Guardian.options()) :: Plug.Conn.t()
    def sign_in(conn, impl, resource, claims \\ %{}, opts \\ []) do
      with {:ok, token, full_claims} <- Guardian.encode_and_sign(impl, resource, claims, opts),
           {:ok, conn} <- add_data_to_conn(conn, resource, token, full_claims, opts),
           {:ok, conn} <- returning_tuple({impl, :after_sign_in, [conn, resource, token, full_claims, opts]}) do
        if session_active?(conn) do
          put_session_token(conn, token, opts)
        else
          conn
        end
      else
        err -> handle_unauthenticated(conn, err, opts)
      end
    end

    @spec sign_out(Plug.Conn.t(), module, Guardian.options()) :: Plug.Conn.t()
    def sign_out(conn, impl, opts \\ []) do
      key = Keyword.get(opts, :key, :all)
      result = do_sign_out(conn, impl, key, opts)

      case result do
        {:ok, conn} ->
          if Keyword.get(opts, :clear_remember_me, false) do
            clear_remember_me(conn, impl, opts)
          else
            conn
          end

        {:error, reason} ->
          handle_unauthenticated(conn, reason, opts)
      end
    end

    @doc """
    Puts a response cookie which replaces the previous `remember_me` cookie
    and is set to immediately expire on the client.

    Note that while this can be used as a cheap way to sign out, a malicious client
    could still access your server using the old JWT from the old cookie.

    In other words, this does not in any way invalidate the token you issued, it just
    makes a compliant client forget it.
    """
    @spec clear_remember_me(Plug.Conn.t(), module, Guardian.options()) :: Plug.Conn.t()
    def clear_remember_me(conn, mod, opts \\ []) do
      key = fetch_token_key(conn, opts)
      # Any value could be used here as the cookie is set to expire immediately anyway
      token = ""

      opts =
        mod
        |> cookie_options(%{})
        |> Keyword.put(:max_age, 0)

      put_resp_cookie(conn, key, token, opts)
    end

    @doc """
    Sets a token of type refresh directly on a cookie.

    The max_age of the cookie till be the expire time of the Token, if available
    If the token does not have an exp,t the default will be 30 days.

    The max age can be overridden by setting the cookie option config.
    """

    @spec remember_me(Plug.Conn.t(), module, any, Guardian.Token.claims(), Guardian.options()) :: Plug.Conn.t()
    def remember_me(conn, mod, resource, claims \\ %{}, opts \\ []) do
      opts = Keyword.put_new(opts, :token_type, "refresh")
      key = fetch_token_key(conn, opts)

      case Guardian.encode_and_sign(mod, resource, claims, opts) do
        {:ok, token, new_claims} ->
          put_resp_cookie(conn, key, token, cookie_options(mod, new_claims))

        {:error, _} = err ->
          handle_unauthenticated(conn, err, opts)
      end
    end

    @spec remember_me_from_token(
            Plug.Conn.t(),
            module,
            Guardian.Token.token(),
            Guardian.Token.claims(),
            Guardian.options()
          ) :: Plug.Conn.t()
    def remember_me_from_token(conn, mod, token, claims_to_check \\ %{}, opts \\ []) do
      token_type = Keyword.get(opts, :token_type, "refresh")
      key = fetch_token_key(conn, opts)

      with {:ok, claims} <- Guardian.decode_and_verify(mod, token, claims_to_check, opts),
           {:ok, _old, {new_t, full_new_c}} <- Guardian.exchange(mod, token, claims["typ"], token_type, opts) do
        put_resp_cookie(conn, key, new_t, cookie_options(mod, full_new_c))
      else
        {:error, _} = err -> handle_unauthenticated(conn, err, opts)
      end
    end

    @spec maybe_halt(Plug.Conn.t(), Keyword.t()) :: Plug.Conn.t()
    def maybe_halt(conn, opts \\ []) do
      if Keyword.get(opts, :halt, true) do
        Plug.Conn.halt(conn)
      else
        conn
      end
    end

    @spec find_token_from_cookies(conn :: Plug.Conn.t(), Keyword.t()) :: {:ok, String.t()} | :no_token_found
    def find_token_from_cookies(conn, opts \\ []) do
      key =
        conn
        |> Pipeline.fetch_key(opts)
        |> token_key()

      token = conn.req_cookies[key] || conn.req_cookies[to_string(key)]
      if token, do: {:ok, token}, else: :no_token_found
    end

    defp fetch_token_key(conn, opts) do
      conn
      |> Pipeline.fetch_key(opts)
      |> token_key()
      |> Atom.to_string()
    end

    defp cookie_options(mod, %{"exp" => timestamp}) do
      max_age = timestamp - Guardian.timestamp()
      Keyword.merge([max_age: max_age], mod.config(:cookie_options, []))
    end

    defp cookie_options(mod, _) do
      Keyword.merge(@default_cookie_max_age, mod.config(:cookie_options, []))
    end

    defp add_data_to_conn(conn, resource, token, claims, opts) do
      conn =
        conn
        |> put_current_token(token, opts)
        |> put_current_claims(claims, opts)
        |> put_current_resource(resource, opts)

      {:ok, conn}
    end

    defp cleanup_session({:ok, conn}, opts) do
      conn =
        if session_active?(conn) do
          key =
            conn
            |> fetch_key(opts)
            |> token_key()

          conn
          |> delete_session(key)
          |> configure_session(renew: true)
        else
          conn
        end

      {:ok, conn}
    end

    defp cleanup_session({:error, _} = err, _opts), do: err
    defp cleanup_session(err, _opts), do: {:error, err}

    defp clear_key(key, {:ok, conn}, impl, opts), do: do_sign_out(conn, impl, key, opts)
    defp clear_key(_, err, _, _), do: err

    defp fetch_key(conn, opts),
      do: Keyword.get(opts, :key) || Pipeline.current_key(conn) || default_key()

    defp remove_data_from_conn(conn, opts) do
      conn =
        conn
        |> put_current_token(nil, opts)
        |> put_current_claims(nil, opts)
        |> put_current_resource(nil, opts)

      {:ok, conn}
    end

    defp revoke_token(conn, impl, key, opts) do
      token = current_token(conn, key: key)

      with {:ok, _} <- impl.revoke(token, opts), do: {:ok, conn}
    end

    defp do_sign_out(%{private: private} = conn, impl, :all, opts) do
      private
      |> Map.keys()
      |> Enum.map(&key_from_other/1)
      |> Enum.filter(&(&1 != nil))
      |> Enum.uniq()
      |> Enum.reduce({:ok, conn}, &clear_key(&1, &2, impl, opts))
      |> cleanup_session(opts)
    end

    defp do_sign_out(conn, impl, key, opts) do
      with {:ok, conn} <- returning_tuple({impl, :before_sign_out, [conn, key, opts]}),
           {:ok, conn} <- revoke_token(conn, impl, key, opts),
           {:ok, conn} <- remove_data_from_conn(conn, key: key) do
        if session_active?(conn) do
          {:ok, delete_session(conn, token_key(key))}
        else
          {:ok, conn}
        end
      end
    end

    defp handle_unauthenticated(conn, reason, opts) do
      error_handler = Pipeline.current_error_handler(conn)

      if error_handler do
        conn
        |> halt()
        |> error_handler.auth_error({:unauthenticated, reason}, opts)
      else
        raise UnauthenticatedError, inspect(reason)
      end
    end
  end
end
