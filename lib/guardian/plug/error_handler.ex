if Code.ensure_loaded?(Plug) do
  defmodule Guardian.Plug.ErrorHandler do
    @moduledoc """
    Optional Behaviour for creating error handlers for `Guardian.Plug.Pipeline`.

    ### Error handler

    When using plugs, you'll need to specify an error handler module.

    The error_handler module requires an `auth_error` function that receives the conn,
    the reason tuple and the options.

    ```elixir
    defmodule MyApp.AuthErrorHandler do
      @behaviour Guardian.Plug.ErrorHandler

      @impl Guardian.Plug.ErrorHandler
      def auth_error(conn, {type, reason}, opts) do
        ...
      end
    end
    ```

    By default, Guardian will emit types of:

    * `:unauthorized`
    * `:invalid_token`
    * `:already_authenticated`
    * `:no_resource_found`
    """

    @callback auth_error(
                conn :: Plug.Conn.t(),
                {type :: atom, reason :: atom},
                opts :: Guardian.options()
              ) :: Plug.Conn.t()
  end
end
