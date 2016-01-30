defmodule Guardian.Phoenix.Controller do
  @moduledoc """
  Provides a simple helper to provide easier access to
  the current user and their claims.

      defmodule MyApp.MyController do
        use MyApp.Web, :controller
        use Guardian.Phoenix.Controller

        def index(conn, params, user, claims) do
          # do stuff in here
        end
      end

  You can specify the key location of the user
  if you're using multiple locations to store users.

      defmodule MyApp.MyController do
        use MyApp.Web, :controller
        use Guardian.Phoenix.Controller, key: :secret

        def index(conn, params, user, claims) do
        # do stuff with the secret user
        end
      end

  By including these helpers they will not prevent your application
  from handling requests when there is no logged in user.
  You will simply get a nil for the user.
  """
  defmacro __using__(opts \\ []) do
    key = Keyword.get(opts, :key, :default)
    quote do
      import Guardian.Plug
      def action(conn, _opts) do
        apply(
          __MODULE__,
          action_name(conn),
          [
            conn,
            conn.params,
            Guardian.Plug.current_resource(conn, unquote(key)),
            Guardian.Plug.claims(conn, unquote(key))
          ]
        )
      end
    end
  end
end
