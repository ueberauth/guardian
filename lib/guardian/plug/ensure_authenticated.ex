if Code.ensure_loaded?(Plug) do
  defmodule Guardian.Plug.EnsureAuthenticated do
    @moduledoc """
    This plug ensures that a valid token was provided and has been verified on the request.

    If one is not found, the `auth_error` will be called with `:unauthenticated`

    This, like all other Guardian plugs, requires a Guardian pipeline to be setup.
    It requires an implementation module, an error handler and a key.

    These can be set either:

    1. Upstream on the connection with `plug Guardian.Pipeline`
    2. Upstream on the connection with `Guardian.Pipeline.{put_module, put_error_handler, put_key}`
    3. Inline with an option of `:module`, `:error_handler`, `:key`

    Options:

    * `claims` - The literal claims to check to ensure that a token is valid
    * `max_age` - If the token has an "auth_time" claim, check it is not older than the maximum age.
    * `key` - The location to find the information in the connection. Defaults to: `default`
    * `halt` - Whether to halt the connection in case of error. Defaults to `true`

    ## Example

    ```elixir
    # setup the upstream pipeline
    plug Guardian.Plug.EnsureAuthenticated, claims: %{"typ" => "access"}
    plug Guardian.Plug.EnsureAuthenticated, key: :secret
    ```

    """

    @behaviour Plug

    @impl Plug
    @spec init(Keyword.t()) :: Keyword.t()
    def init(opts), do: opts

    @impl Plug
    @spec call(conn :: Plug.Conn.t(), opts :: Keyword.t()) :: Plug.Conn.t()
    def call(conn, opts) do
      conn
      |> Guardian.Plug.current_token(opts)
      |> verify(conn, opts)
      |> respond()
    end

    @spec verify(token :: Guardian.Token.token(), conn :: Plug.Conn.t(), opts :: Keyword.t()) ::
            {{:ok, Guardian.Token.claims()} | {:error, any}, Plug.Conn.t(), Keyword.t()}
    defp verify(nil, conn, opts), do: {{:error, :unauthenticated}, conn, opts}

    defp verify(_token, conn, opts) do
      result =
        conn
        |> Guardian.Plug.current_claims(opts)
        |> verify_claims(opts)

      {result, conn, opts}
    end

    @spec respond({{:ok, Guardian.Token.claims()} | {:error, any}, Plug.Conn.t(), Keyword.t()}) :: Plug.Conn.t()
    defp respond({{:ok, _}, conn, _opts}), do: conn

    defp respond({{:error, reason}, conn, opts}) do
      conn
      |> Guardian.Plug.Pipeline.fetch_error_handler!(opts)
      |> apply(:auth_error, [conn, {:unauthenticated, reason}, opts])
      |> Guardian.Plug.maybe_halt(opts)
    end

    @spec verify_claims(Guardian.Token.claims(), Keyword.t()) :: {:ok, Guardian.Token.claims()} | {:error, any}
    defp verify_claims(claims, opts) do
      to_check = Keyword.get(opts, :claims)
      Guardian.Token.Verify.verify_literal_claims(claims, to_check, opts)
    end
  end
end
