if Code.ensure_loaded?(Plug) do
  defmodule Guardian.Plug.EnsureNotAuthenticated do
    @moduledoc """
    This plug ensures that a resource is not logged in.

    If one is not found, the `auth_error` will be called with `:already_authenticated`

    This, like all other Guardian plugs, requires a Guardian pipeline to be setup.
    It requires an implementation module, an error handler and a key.

    These can be set either:

    1. Upstream on the connection with `plug Guardian.Pipeline`
    2. Upstream on the connection with `Guardian.Pipeline.{put_module, put_error_handler, put_key}`
    3. Inline with an option of `:module`, `:error_handler`, `:key`

    Options:

    * `key` - The location to find the information in the connection. Defaults to: `default`
    * `halt` - Whether to halt the connection in case of error. Defaults to `true`

    ## Example

    ```elixir

    # setup the upstream pipeline
    plug Guardian.Plug.EnsureNotAuthenticated
    plug Guardian.Plug.EnsureNotAuthenticated, key: :secret
    ```

    """

    @behaviour Plug

    @impl Plug
    @spec init(opts :: Keyword.t()) :: Keyword.t()
    def init(opts), do: opts

    @impl Plug
    @spec call(conn :: Plug.Conn.t(), opts :: Keyword.t()) :: Plug.Conn.t()
    def call(conn, opts) do
      token = Guardian.Plug.current_token(conn, opts)

      if token do
        conn
        |> Guardian.Plug.Pipeline.fetch_error_handler!(opts)
        |> apply(:auth_error, [conn, {:already_authenticated, :already_authenticated}, opts])
        |> Guardian.Plug.maybe_halt(opts)
      else
        conn
      end
    end
  end
end
