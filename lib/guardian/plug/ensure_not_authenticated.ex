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

    ## Example

    ```elixir

      # setup the upstream pipeline
      plug Guardian.Plug.EnsureNotAuthenticated
      plug Guardian.Plug.EnsureNotAuthenticated, key: :secret
      ```
    """
    import Plug.Conn

    alias Guardian.Plug, as: GPlug
    alias GPlug.{Pipeline}

    def init(opts), do: opts

    def call(conn, opts) do
      token = GPlug.current_token(conn, opts)

      if token do
        conn
        |> Pipeline.fetch_error_handler!(opts)
        |> apply(:auth_error, [conn, {:already_authenticated, :already_authenticated}, opts])
        |> halt()
      else
        conn
      end
    end
  end
end
