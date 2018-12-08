if Code.ensure_loaded?(Plug) do
  defmodule Guardian.Plug.VerifyHeader do
    @moduledoc """

    Looks for and validates a token found in the `Authorization` header.

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

    Options:

    * `claims` - The literal claims to check to ensure that a token is valid
    * `realm` - The prefix for the token in the Authorization header. Defaults to `Bearer`. `:none` will not use a prefix.
    * `key` - The location to store the information in the connection. Defaults to: `default`

    ### Example

    ```elixir

    # setup the upstream pipeline

    plug Guardian.Plug.VerifyHeader, claims: %{typ: "access"}

    ```

    This will check the authorization header for a token

    `Authorization: Bearer <token>`

    This token will be placed into the connection depending on the key and can be accessed with
    `Guardian.Plug.current_token` and `Guardian.Plug.current_claims`

    OR

    `MyApp.ImplementationModule.current_token` and `MyApp.ImplementationModule.current_claims`
    """

    alias Guardian.Plug.Pipeline

    import Plug.Conn

    @behaviour Plug

    @impl Plug
    @spec init(opts :: Keyword.t()) :: Keyword.t()
    def init(opts \\ []) do
      realm = Keyword.get(opts, :realm, "Bearer")

      case realm do
        "" ->
          opts

        :none ->
          opts

        _realm ->
          {:ok, reg} = Regex.compile("#{realm}\:?\s+(.*)$", "i")
          Keyword.put(opts, :realm_reg, reg)
      end
    end

    @impl Plug
    @spec call(Plug.Conn.t(), Keyword.t()) :: Plug.Conn.t()
    def call(conn, opts) do
      with nil <- Guardian.Plug.current_token(conn, opts),
           {:ok, token} <- fetch_token_from_header(conn, opts),
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

    @spec fetch_token_from_header(Plug.Conn.t(), Keyword.t()) ::
            :no_token_found
            | {:ok, String.t()}
    defp fetch_token_from_header(conn, opts) do
      headers = get_req_header(conn, "authorization")
      fetch_token_from_header(conn, opts, headers)
    end

    @spec fetch_token_from_header(Plug.Conn.t(), Keyword.t(), Keyword.t()) ::
            :no_token_found
            | {:ok, String.t()}
    defp fetch_token_from_header(_, _, []), do: :no_token_found

    defp fetch_token_from_header(conn, opts, [token | tail]) do
      reg = Keyword.get(opts, :realm_reg, ~r/^(.*)$/)
      trimmed_token = String.trim(token)

      case Regex.run(reg, trimmed_token) do
        [_, match] -> {:ok, String.trim(match)}
        _ -> fetch_token_from_header(conn, opts, tail)
      end
    end

    @spec storage_key(Plug.Conn.t(), Keyword.t()) :: String.t()
    defp storage_key(conn, opts), do: Pipeline.fetch_key(conn, opts)
  end
end
