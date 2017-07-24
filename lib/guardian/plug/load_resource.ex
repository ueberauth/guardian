if Code.ensure_loaded?(Plug) do
  defmodule Guardian.Plug.LoadResource do
    @moduledoc """
    This plug loads the resource associated with a previously
    validated token. Tokens are found and validated using the `Verify*` plugs.

    By default, load resource will return an error if no resource can be found.
    You can override this behaviour using the `allow_blank: true` option.

    If `allow_blank` is not set to true, the plug will return an error
    if no resource can be found with `:no_resource_found`

    This, like all other Guardian plugs, requires a Guardian pipleine to be setup.
    It requires an implementation module, an error handler and a key.

    These can be set either:

    1. Upstream on the connection with `plug Guardian.Pipeline`
    2. Upstream on the connection with `Guardian.Pipeline.{put_module, put_error_handler, put_key}`
    3. Inline with an option of `:module`, `:erorr_handler`, `:key`

    Options:

    * `allow_blank` - boolean. If set to true, will try to load a resource but will not fail if no resource is found.
    * `key` - The location to find the information in the connection. Defaults to: `deafult`

    ## Example

    ```elixir

      # setup the upstream pipeline
      plug Guardian.Plug.LoadResource, allow_blank: true
      plug Guardian.Plug.LoadResource, key: :secret
      ```
    """

    import Plug.Conn

    alias Guardian.Plug, as: GPlug
    alias GPlug.{Pipeline}

    def init(opts), do: opts

    def call(conn, opts) do
      claims = GPlug.current_claims(conn, opts)
      allow_blank? = Keyword.get(opts, :allow_blank)
      module = Pipeline.fetch_module!(conn, opts)

      if claims do
        result = apply(module, :resource_from_claims, [claims])
        case result do
          {:ok, resource} ->
            GPlug.put_current_resource(conn, resource, opts)
          {:error, reason} ->
            if allow_blank?, do: conn, else: return_error(conn, reason, opts)
          _ ->
            if allow_blank?, do: conn, else: return_error(conn, opts)
        end
      else
        if allow_blank?, do: conn, else: return_error(conn, opts)
      end
    end

    defp return_error(conn, opts) do
      return_error(conn, :no_resource_found, opts)
    end

    defp return_error(conn, reason, opts) do
      handler = Pipeline.fetch_error_handler!(conn, opts)
      conn = apply(handler, :auth_error, [conn, {:no_resource_found, reason}, opts])
      halt(conn)
    end
  end
end
