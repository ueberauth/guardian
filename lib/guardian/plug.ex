if Code.ensure_loaded?(Plug) do
  defmodule Guardian.Plug do
    @moduledoc """
    Provides functions for the implementation module for dealing with
    Guardain in a Plug environment

    ```elixir
    defmodule MyApp.Tokens do
      use Guardian, otp_app: :my_app

      # ... snip
    end
    ```

    Your implementation module will be given a `Plug` module for
    interacting with plug.

    If you're using Guardian in your application most of the setters will
    be unintersting. They're mostly for library authors and Guardian itself.

    The usual functions you'd use in your application are:

    ### `sign_in(conn, resource, claims \\ %{}, opts \\ [])`

    Sign in a resource for your application.
    This will generate a token for your resource according to
    your TokenModule and `subject_for_token` callback.

    `sign_in` will also cache the `resource`, `claims`, and `token` on the
    connection.

    ```elixir
    {:ok, conn} = MyApp.Guardian.Plug.sign_in(conn, resource, my_custom_claims)

    # OR

    conn = MyApp.Guardian.Plug.sign_in!(conn, resource, my_custom_claims)
    ```

    If there is a session present the token will be stored in the session
    to provide traditional session based authentication.
    """

    @default_key "default"

    import Guardian.Plug.Keys
    import Plug.Conn

    alias Guardian.Plug, as: GPlug
    alias GPlug.Pipeline

    defmacro __using__(impl) do
      quote do
        def implementation, do: unquote(impl)

        def put_current_token(conn, token, opts \\ []),
          do: GPlug.put_current_token(conn, token, opts)

        def put_current_claims(conn, claims, opts \\ []),
          do: GPlug.put_current_claims(conn, claims, opts)

        def put_current_resource(conn, resource, opts \\ []),
          do: GPlug.put_current_resource(conn, resource, opts)

        def current_token(conn, opts \\ []),
          do: GPlug.current_token(conn, opts)

        def current_claims(conn, opts \\ []),
          do: GPlug.current_claims(conn, opts)

        def current_resource(conn, opts \\ []),
          do: GPlug.current_resource(conn, opts)

        def authenticated?(conn, opts \\ []),
          do: GPlug.authenticated?(conn, opts)

        def sign_in(conn, resource, claims \\ %{}, opts \\ []),
          do: GPlug.sign_in(conn, implementation(), resource, claims, opts)

        def sign_in!(conn, resource, claims \\ %{}, opts \\ []),
          do: GPlug.sign_in!(conn, implementation(), resource, claims, opts)

        def sign_out(conn, opts \\ []),
          do: GPlug.sign_out(conn, implementation(), opts)

        def sign_out!(conn, opts \\ []),
          do: GPlug.sign_out!(conn, implementation(), opts)

        def remember_me(conn, resource, claims, opts),
          do: GPlug.remember_me(conn, implementation(), resource, claims, opts)

        def remember_me!(conn, resource, claims, opts),
          do: GPlug.remember_me!(conn, implementation(), resource, claims, opts)

        def remember_me_from_token(conn, token, claims_to_check \\ %{}, opts \\ []),
          do: GPlug.remember_me_from_token(conn, implementation(), token, claims_to_check, opts)

        def remember_me_from_token!(conn, token, claims_to_check \\ %{}, opts \\ []),
          do: GPlug.remember_me_from_token!(conn, implementation(), token, claims_to_check, opts)
      end
    end

    def session_active?(conn) do
      key = :seconds |> System.os_time() |> to_string()
      get_session(conn, key) == nil
    rescue
      ArgumentError -> false
    end

    @spec authenticated?(Plug.Conn.t, Guardian.opts) :: true | false
    def authenticated?(conn, opts) do
      key =
        conn
        |> fetch_key(opts)
        |> token_key()

      conn.private[key] != nil
    end

    @doc """
    Provides the default key for the location of a token in the session and connection
    """

    @spec default_key() :: String.t
    def default_key, do: @default_key

    @spec current_claims(Plug.Conn.t, Guardian.opts) :: Guardian.Token.claims | nil
    def current_claims(conn, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> claims_key()

      conn.private[key]
    end

    @spec current_resource(Plug.Conn.t, Guardian.opts) :: any | nil
    def current_resource(conn, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> resource_key()

      conn.private[key]
    end

    @spec current_token(Plug.Conn.t, Guardian.opts) :: Guardian.Token.token | nil
    def current_token(conn, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> token_key()

      conn.private[key]
    end

    @spec put_current_token(Plug.Conn.t, Guardian.Token.token | nil, Guardian.opts) :: Plug.Conn.t
    def put_current_token(conn, token, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> token_key()

      put_private(conn, key, token)
    end

    @spec put_current_claims(Plug.Conn.t, Guardian.Token.claims | nil, Guardian.opts) :: Plug.Conn.t
    def put_current_claims(conn, claims, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> claims_key()

      put_private(conn, key, claims)
    end

    @spec put_current_resource(Plug.Conn.t, resource :: any | nil, Guardian.opts) :: Plug.Conn.t
    def put_current_resource(conn, resource, opts \\ []) do
      key =
        conn
        |> fetch_key(opts)
        |> resource_key()

      put_private(conn, key, resource)
    end

    @spec sign_in(Plug.Conn.t, module, any, Guardian.Token.claims, Guardian.opts) :: {:ok, Plug.Conn.t} | {:error, atom}
    def sign_in(conn, impl, resource, claims \\ %{}, opts \\ []) do
      with {:ok, token, full_claims} <- Guardian.encode_and_sign(impl, resource, claims, opts),
           {:ok, conn} <- add_data_to_conn(conn, resource, token, full_claims, opts),
           result <- apply(impl, :after_sign_in, [conn, resource, token, full_claims, opts]),
           {:ok, conn} <- Guardian.validate_conditional_tuple(result, {impl, :after_sign_in}) do
        if session_active?(conn) do
          key =
            conn
            |> fetch_key(opts)
            |> token_key()

          conn =
            conn
            |> put_session(key, token)
            |> configure_session(renew: true)

          {:ok, conn}
        else
          {:ok, conn}
        end
      end
    end

    @spec sign_in!(Plug.Conn.t, module, any, Guardian.Token.claims, Guardian.opts) :: Plug.Conn.t
    def sign_in!(conn, impl, resource, claims \\ %{}, opts \\ []) do
      result = __MODULE__.sign_in(conn, impl, resource, claims, opts)
      case result do
        {:ok, conn} -> conn
        {:error, reason} -> raise inspect(reason)
      end
    end

    @spec sign_out(Plug.Conn.t, module, Guardian.opts) :: {:ok, Plug.Conn.t} | {:error, atom}
    def sign_out(conn, impl, opts) do
      key = Keyword.get(opts, :key, :all)
      do_sign_out(conn, impl, key, opts)
    end

    @spec sign_out!(Plug.Conn.t, module, Guardian.opts) :: Plug.Conn.t
    def sign_out!(conn, impl, opts) do
      result = __MODULE__.sign_out(conn, impl, opts)
      case result do
        {:ok, conn} -> conn
        {:error, reason} -> raise inspect(reason)
      end
    end

    @spec remember_me(Plug.Conn.t, module, any, Guardian.Token.claims, Guardian.opts) :: {:ok, Plug.Conn.t} |
                                                                                         {:error, atom}
    def remember_me(conn, mod, resource, claims, opts) do
      with type <- Keyword.get(opts, :token_type, "refresh"),
           opts <- Keyword.put(opts, :token_type, type),
           key <- Pipeline.fetch_key(conn, opts),
           {:ok, token, _claims} <- Guardian.encode_and_sign(mod, resource, claims, opts) do

        {:ok, put_resp_cookie(conn, key, token)}
      else
        {:error, _} = err -> err
      end
    end

    @spec remember_me!(Plug.Conn.t, module, any, Guardian.Token.claims, Guardian.opts) :: Plug.Conn.t
    def remember_me!(conn, mod, resource, claims, opts) do
      result = __MODULE__.remember_me(conn, mod, resource, claims, opts)
      case result do
        {:ok, conn} -> conn
        {:error, reason} ->
          raise inspect(reason)
      end
    end

    @spec remember_me_from_token(
      Plug.Conn.t, module, Guardian.Token.token, Guardian.Token.claims, Guardian.opts
    ) :: {:ok, Plug.Conn.t} | {:error, atom}
    def remember_me_from_token(conn, mod, token, claims_to_check \\ %{}, opts \\ []) do
      with {:ok, claims} <- Guardian.decode_and_verify(mod, token, claims_to_check, opts),
           type <- Keyword.get(opts, :token_type, "refresh"),
           key <- Pipeline.fetch_key(conn, opts),
           {:ok, _old, {new_t, _new_c}} <- Guardian.exchange(mod, token, claims["typ"], type, opts) do

        {:ok, put_resp_cookie(conn, key, new_t)}
      else
        {:error, _} = err -> err
      end
    end

    @spec remember_me_from_token!(
      Plug.Conn.t, module, Guardian.Token.token, Guardian.Token.claims, Guardian.opts
    ) :: Plug.Conn.t
    def remember_me_from_token!(conn, mod, token, claims_to_check \\ %{}, opts \\ []) do
      result = __MODULE__.remember_me_from_token(conn, mod, token, claims_to_check, opts)
      case result do
        {:ok, conn} -> conn
        {:error, reason} ->
          raise inspect(reason)
      end
    end

    defp add_data_to_conn(conn, resource, token, claims, opts) do
      conn =
        conn
        |> put_current_token(token, opts)
        |> put_current_claims(claims, opts)
        |> put_current_resource(resource, opts)

      {:ok, conn}
    end

    defp cleanup_session({:ok, conn}) do
      if session_active?(conn) do
        {:ok, configure_session(conn, drop: true)}
      else
        {:ok, conn}
      end
    end
    defp cleanup_session({:error, _} = err), do: err
    defp cleanup_session(err), do: {:error, err}

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

    defp do_sign_out(%{private: private} = conn, impl, :all, opts) do
      private
      |> Map.keys()
      |> Enum.map(&key_from_other/1)
      |> Enum.filter(&(&1 != nil))
      |> Enum.uniq()
      |> Enum.reduce({:ok, conn}, &clear_key(&1, &2, impl, opts))
      |> cleanup_session()
    end

    defp do_sign_out(conn, impl, key, opts) do
      with result <- apply(impl, :before_sign_out, [conn, key, opts]),
           {:ok, conn} <- Guardian.validate_conditional_tuple(result, {impl, :before_sign_out}),
           {:ok, conn} <- remove_data_from_conn(conn, key: key)
      do
        if session_active?(conn) do
          {:ok, delete_session(conn, token_key(key))}
        else
          {:ok, conn}
        end
      end
    end
  end
end
