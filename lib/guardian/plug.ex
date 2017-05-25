defmodule Guardian.Plug do
  @moduledoc false

  @default_key "default"

  import Guardian.Plug.Keys
  import Plug.Conn

  defmacro __using__(impl) do
    quote do
      alias Guardian.Plug, as: GPLUG__
      def implementation, do: unquote(impl)

      def set_current_token(conn, token, options \\ []) do
        GPLUG__.set_current_token(conn, token, options)
      end

      def set_current_claims(conn, claims, options \\ []) do
        GPLUG__.set_current_claims(conn, claims, options)
      end

      def set_current_resource(conn, resource, options \\ []) do
        GPLUG__.set_current_resource(conn, resource, options)
      end

      def current_token(conn, options \\ []) do
        GPLUG__.current_token(conn, options)
      end

      def current_claims(conn, options \\ []) do
        GPLUG__.current_claims(conn, options)
      end

      def current_resource(conn, options \\ []) do
        GPLUG__.current_resource(conn, options)
      end

      def authenticated?(conn, options \\ []) do
        GPLUG__.authenticated?(conn, options)
      end

      def sign_in(conn, resource, claims \\ %{}, opts \\ []) do
        GPLUG__.sign_in(
          conn, implementation(), resource, claims, opts
        )
      end

      def sign_out(conn, options \\ []) do
        GPLUG__.sign_out(conn, implementation(), options)
      end
    end
  end

  @spec set_current_token(
          conn :: Plug.Conn.t(),
          token :: Guardian.Token.token() | nil,
          options :: Guardian.options()
        ) :: Plug.Conn.t()
  def set_current_token(conn, token, options) do
    key =
      options
      |> key_from_options()
      |> token_key()

    put_private(conn, key, token)
  end

  @spec set_current_claims(
          conn :: Plug.Conn.t(),
          claims :: Guardian.Token.claims() | nil,
          options :: Guardian.options()
        ) :: Plug.Conn.t()
  def set_current_claims(conn, claims, options) do
    key =
      options
      |> key_from_options()
      |> claims_key()

    put_private(conn, key, claims)
  end

  @spec set_current_resource(
          conn :: Plug.Conn.t(),
          resource :: any() | nil,
          options :: Guardian.options()
        ) :: Plug.Conn.t()
  def set_current_resource(conn, resource, options) do
    key =
      options
      |> key_from_options()
      |> resource_key()

    put_private(conn, key, resource)
  end

  @spec current_token(
          conn :: Plug.Conn.t(),
          options :: Guardian.options()
        ) :: Guardian.Token.token() | nil
  def current_token(conn, options) do
    key =
      options
      |> key_from_options()
      |> token_key()

    conn.private[key]
  end

  @spec current_claims(
          conn :: Plug.Conn.t(),
          options :: Guardian.options()
        ) :: Guardian.Token.claims() | nil
  def current_claims(conn, options) do
    key =
      options
      |> key_from_options()
      |> claims_key()

    conn.private[key]
  end

  @spec current_resource(
          conn :: Plug.Conn.t(),
          options :: Guardian.options()
        ) :: any() | nil
  def current_resource(conn, options) do
    key =
      options
      |> key_from_options()
      |> resource_key()

    conn.private[key]
  end

  @spec authenticated?(
          conn :: Plug.Conn.t(),
          options :: Guardian.options()
        ) :: true | false
  def authenticated?(conn, options) do
    key =
      options
      |> key_from_options()
      |> token_key()

    conn.private[key] != nil
  end

  @spec sign_in(
    conn :: Plug.Conn.t(),
    impl :: Module.t(),
    resource :: any(),
    claims :: Guardian.Token.claims(),
    options :: Guardian.options()
  ) :: {:ok, Plug.Conn.t()} | {:error, atom()}
  def sign_in(
    conn,
    impl,
    resource,
    claims \\ %{},
    options \\ []
  ) do
    with {:ok, token, full_claims} <- Guardian.encode_and_sign(
           impl, resource, claims, options
         ),
         {:ok, conn} <- add_data_to_conn(
           conn, resource, token, full_claims, options
         ),
         {:ok, conn} <- apply(
           impl, :after_sign_in, [conn, resource, token, full_claims, options]
         )
    do
      case conn.req_cookies do
        %Plug.Conn.Unfetched{} -> {:ok, conn}
        _ ->
          {:ok, put_session(conn, token_key(key_from_options(options)), token)}
      end
    else
      {:error, _} = err -> err
      err -> {:error, err}
    end
  end

  @spec sign_out(
    conn :: Plug.Conn.t(),
    impl :: Module.t(),
    options :: Guardian.options()
  ) :: {:ok, Plug.Conn.t()} | {:error, atom()}
  def sign_out(conn, impl, options) do
    key = Keyword.get(options, :key, :all)
    do_sign_out(conn, impl, key, options)
  end

  defp do_sign_out(%{private: private} = conn, impl, :all, options) do
    result =
      private
      |> Map.keys()
      |> Enum.map(&key_from_other/1)
      |> Enum.filter(&(&1 != nil))
      |> Enum.uniq()
      |> Enum.reduce(
        {:ok, conn},
        fn key, {:ok, conn} -> do_sign_out(conn, impl, key, options)
           _key, err -> err
        end
      )

    with {:ok, conn} <- result do
      case conn.req_cookies do
        %Plug.Conn.Unfetched{} -> {:ok, conn}
        _ ->
          {:ok, configure_session(conn, drop: true)}
      end
    else
      {:error, _} = err -> err
      err -> {:error, err}
    end
  end

  defp do_sign_out(conn, impl, key, options) do
    with {:ok, conn} <- apply(impl, :before_sign_out, [conn, key, options]),
         {:ok, conn} <- remove_data_from_conn(conn, key: key)
    do
      case conn.req_cookies do
        %Plug.Conn.Unfetched{} -> {:ok, conn}
        _ ->
          {:ok, delete_session(conn, token_key(key))}
      end
    end
  end

  defp add_data_to_conn(conn, resource, token, claims, options) do
    conn =
      conn
      |> set_current_token(token, options)
      |> set_current_claims(claims, options)
      |> set_current_resource(resource, options)
    {:ok, conn}
  end

  defp remove_data_from_conn(conn, options) do
    conn =
      conn
      |> set_current_token(nil, options)
      |> set_current_claims(nil, options)
      |> set_current_resource(nil, options)
    {:ok, conn}
  end

  defp key_from_options(opts) do
    Keyword.get(opts, :key, @default_key)
  end
end
