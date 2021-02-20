if Code.ensure_loaded?(Plug) do
  defmodule Guardian.Plug.LoadResource do
    @moduledoc """
    This plug loads the resource associated with a previously
    validated token. Tokens are found and validated using the `Verify*` plugs.

    By default, load resource will return an error if no resource can be found.
    You can override this behaviour using the `allow_blank: true` option.

    If `allow_blank` is not set to true, the plug will return an error
    if no resource can be found with `:no_resource_found`

    This, like all other Guardian plugs, requires a Guardian pipeline to be setup.
    It requires an implementation module, an error handler and a key.

    These can be set either:

    1. Upstream on the connection with `plug Guardian.Pipeline`
    2. Upstream on the connection with `Guardian.Pipeline.{put_module, put_error_handler, put_key}`
    3. Inline with an option of `:module`, `:error_handler`, `:key`

    Options:

    * `allow_blank` - boolean. If set to true, will try to load a resource but
      will not fail if no resource is found.
    * `key` - The location to find the information in the connection. Defaults to: `default`
    * `halt` - Whether to halt the connection in case of error. Defaults to `true`

    ## Example

    ```elixir
    # setup the upstream pipeline
    plug Guardian.Plug.LoadResource, allow_blank: true
    plug Guardian.Plug.LoadResource, key: :secret
    ```

    """

    alias Guardian.Plug.Pipeline

    @behaviour Plug

    @impl Plug
    @spec init(opts :: Keyword.t()) :: Keyword.t()
    def init(opts), do: opts

    @impl Plug
    @spec call(conn :: Plug.Conn.t(), opts :: Keyword.t()) :: Plug.Conn.t()
    def call(conn, opts) do
      allow_blank = Keyword.get(opts, :allow_blank)

      conn
      |> Guardian.Plug.current_claims(opts)
      |> resource(conn, opts)
      |> respond(allow_blank)
    end

    defp resource(nil, conn, opts), do: {:error, :no_resource_found, conn, opts}

    defp resource(claims, conn, opts) do
      module = Pipeline.fetch_module!(conn, opts)

      case apply(module, :resource_from_claims, [claims]) do
        {:ok, resource} -> {:ok, resource, conn, opts}
        {:error, reason} -> {:error, reason, conn, opts}
        _ -> {:error, :no_resource_found, conn, opts}
      end
    end

    defp respond({:error, _reason, conn, _opts}, true), do: conn
    defp respond({:error, reason, conn, opts}, _), do: return_error(conn, reason, opts)

    defp respond({:ok, resource, conn, opts}, _),
      do: Guardian.Plug.put_current_resource(conn, resource, opts)

    defp return_error(conn, reason, opts) do
      handler = Pipeline.fetch_error_handler!(conn, opts)
      conn = apply(handler, :auth_error, [conn, {:no_resource_found, reason}, opts])
      Guardian.Plug.maybe_halt(conn, opts)
    end
  end
end
