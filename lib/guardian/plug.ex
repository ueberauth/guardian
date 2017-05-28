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
  {:ok, token, claims} =
    MyApp.Tokens.Plug.sign_in(conn, resource, my_custom_claims)
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

      def set_current_token(conn, token, opts \\ []),
        do: GPlug.set_current_token(conn, token, opts)

      def set_current_claims(conn, claims, opts \\ []),
        do: GPlug.set_current_claims(conn, claims, opts)

      def set_current_resource(conn, resource, opts \\ []),
        do: GPlug.set_current_resource(conn, resource, opts)

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

      def sign_out(conn, opts \\ []),
        do: GPlug.sign_out(conn, implementation(), opts)
    end
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
  def current_claims(conn, opts) do
    key =
      conn
      |> fetch_key(opts)
      |> claims_key()

    conn.private[key]
  end

  @spec current_resource(Plug.Conn.t, Guardian.opts) :: any | nil
  def current_resource(conn, opts) do
    key =
      conn
      |> fetch_key(opts)
      |> resource_key()

    conn.private[key]
  end

  @spec current_token(Plug.Conn.t, Guardian.opts) :: Guardian.Token.token | nil
  def current_token(conn, opts) do
    key =
      conn
      |> fetch_key(opts)
      |> token_key()

    conn.private[key]
  end

  @spec set_current_token(Plug.Conn.t, Guardian.Token.token | nil, Guardian.opts) :: Plug.Conn.t
  def set_current_token(conn, token, opts) do
    key =
      conn
      |> fetch_key(opts)
      |> token_key()

    put_private(conn, key, token)
  end

  @spec set_current_claims(Plug.Conn.t, Guardian.Token.claims | nil, Guardian.opts) :: Plug.Conn.t
  def set_current_claims(conn, claims, opts) do
    key =
      conn
      |> fetch_key(opts)
      |> claims_key()

    put_private(conn, key, claims)
  end

  @spec set_current_resource(Plug.Conn.t, resource :: any | nil, Guardian.opts) :: Plug.Conn.t
  def set_current_resource(conn, resource, opts) do
    key =
      conn
      |> fetch_key(opts)
      |> resource_key()

    put_private(conn, key, resource)
  end

  @spec sign_in(Plug.Conn.t, Module.t, any, Guardian.Token.claims, Guardian.opts) :: {:ok, Plug.Conn.t} | {:error, atom}
  def sign_in(conn, impl, resource, claims \\ %{}, opts \\ []) do
    with {:ok, token, full_claims} <- Guardian.encode_and_sign(impl, resource, claims, opts),
         {:ok, conn} <- add_data_to_conn(conn, resource, token, full_claims, opts),
         {:ok, conn} <- apply(impl, :after_sign_in, [conn, resource, token, full_claims, opts])
    do
      case conn.req_cookies do
        %Plug.Conn.Unfetched{} -> {:ok, conn}
        _ ->
          key =
            conn
            |> fetch_key(opts)
            |> token_key()

          {:ok, put_session(conn, key, token)}
      end
    else
      {:error, _} = err -> err
      err -> {:error, err}
    end
  end

  @spec sign_out(Plug.Conn.t, Module.t, Guardian.opts) :: {:ok, Plug.Conn.t} | {:error, atom}
  def sign_out(conn, impl, opts) do
    key = Keyword.get(opts, :key, :all)
    do_sign_out(conn, impl, key, opts)
  end

  defp add_data_to_conn(conn, resource, token, claims, opts) do
    conn =
      conn
      |> set_current_token(token, opts)
      |> set_current_claims(claims, opts)
      |> set_current_resource(resource, opts)

    {:ok, conn}
  end

  defp cleanup_session({:ok, %{req_cookies: %Plug.Conn.Unfetched{}} = conn}),
    do: {:ok, conn}
  defp cleanup_session({:ok, conn}),
    do: {:ok, configure_session(conn, drop: true)}
  defp cleanup_session({:error, _} = err), do: err
  defp cleanup_session(err), do: {:error, err}

  defp clear_key(key, {:ok, conn}, impl, opts), do: do_sign_out(conn, impl, key, opts)
  defp clear_key(_, err, _, _), do: err

  defp fetch_key(conn, opts),
    do: Keyword.get(opts, :key) || Pipeline.current_key(conn) || default_key()

  defp remove_data_from_conn(conn, opts) do
    conn =
      conn
      |> set_current_token(nil, opts)
      |> set_current_claims(nil, opts)
      |> set_current_resource(nil, opts)

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
    with {:ok, conn} <- apply(impl, :before_sign_out, [conn, key, opts]),
         {:ok, conn} <- remove_data_from_conn(conn, key: key)
    do
      case conn.req_cookies do
        %Plug.Conn.Unfetched{} -> {:ok, conn}
        _ ->
          {:ok, delete_session(conn, token_key(key))}
      end
    end
  end
end
