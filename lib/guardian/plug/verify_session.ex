if Code.ensure_loaded?(Plug) do
  defmodule Guardian.Plug.VerifySession do
    @moduledoc """
    Looks for and validates a token found in the session.

    In the case where:

    a. The session is not loaded
    b. A token is already found for `:key`

    This plug will not do anything.

    This, like all other Guardian plugs, requires a Guardian pipeline to be setup.
    It requires an implementation module, an error handler and a key.

    These can be set either:

    1. Upstream on the connection with `plug Guardian.Pipeline`
    2. Upstream on the connection with `Guardian.Pipeline.{put_module, put_error_handler, put_key}`
    3. Inline with an option of `:module`, `:error_handler`, `:key`

    If a token is found but is invalid, the error handler will be called with
    `auth_error(conn, {:invalid_token, reason}, opts)`

    Once a token has been found it will be decoded, the token and claims will be put onto the connection.

    They will be available using `Guardian.Plug.current_claims/2` and `Guardian.Plug.current_token/2`
    """

    import Plug.Conn
    import Guardian.Plug.Keys

    alias Guardian.Plug.Pipeline

    @behaviour Plug

    @impl Plug
    @spec init(opts :: Keyword.t()) :: Keyword.t()
    def init(opts), do: opts

    @impl Plug
    @spec call(conn :: Plug.Conn.t(), opts :: Keyword.t()) :: Plug.Conn.t()
    def call(conn, opts) do
      if Guardian.Plug.session_active?(conn) do
        verify_session(conn, opts)
      else
        conn
      end
    end

    defp verify_session(conn, opts) do
      with nil <- Guardian.Plug.current_token(conn, opts),
           {:ok, token} <- find_token_from_session(conn, opts),
           module <- Pipeline.fetch_module!(conn, opts),
           claims_to_check <- Keyword.get(opts, :claims, %{}),
           key <- storage_key(conn, opts),
           {:ok, claims} <- Guardian.decode_and_verify(module, token, claims_to_check, opts) do
        conn
        |> Guardian.Plug.put_current_token(token, key: key)
        |> Guardian.Plug.put_current_claims(claims, key: key)
      else
        :no_token_found ->
          conn

        {:error, reason} ->
          conn
          |> Pipeline.fetch_error_handler!(opts)
          |> apply(:auth_error, [conn, {:invalid_token, reason}, opts])
          |> halt()

        _ ->
          conn
      end
    end

    defp find_token_from_session(conn, opts) do
      key = conn |> storage_key(opts) |> token_key()
      token = get_session(conn, key)
      if token, do: {:ok, token}, else: :no_token_found
    end

    defp storage_key(conn, opts), do: Pipeline.fetch_key(conn, opts)
  end
end
