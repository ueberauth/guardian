defmodule Guardian.Plug.Pipeline do
  @moduledoc """
  Helps to build plug pipelines for use with Guardian and associated plugs.

  All Guardian provided plugs have a number of features.

  1. They take a `:key` option to know where to store information in the session and connection
  2. They require a reference to the implementation (the module that `use Guardian`)
  3. They require a reference to an error handling module

  These references are passed through the connection so they must be put in place
  before the Guardian Plugs. By using a pipeline this is taken care of for you.

  The easiest way to use `Guardian.Plug.Pipeline` is to create a module that defines your pipeline.

  ```elixir
  defmodule MyApp.AuthPipeline do
    use Guardian.Plug.Pipeline, otp_app: :my_app,
                                module: MyApp.Tokens,
                                error_handler: MyApp.AuthErrorHandler

    alias Guardian.Plug.{
      EnsureAuthenticated,
      LoadResource,
      VerifySession,
      VerifyHeader,
    }

    plug VerifySession, claims: @claims
    plug VerifyHeader, claims: @claims, realm: "Bearer"
    plug EnsureAuthenticated
    plug LoadResource, ensure: true
  end
  ```

  When you want to use the pipeline you just use it like a normal plug.

  ```elixir
  plug MyApp.AuthPipeline
  ```

  This pipeline will look for tokens in either the session (it's ok if it's not loaded)
  followed by the header if one wasn't found in the session.

  We then ensure that we found a token and fail if not.

  Given that we found a token, we then attempt to load the resource the token
  refres to, failing if one is not found.

  ### Customizing your pipeline

  Once you've created a pipeline, you can customize it when you call it with options.

  ```elixir
  plug MyApp.AuthPipeline, module: MyApp.ADifferentGuardianModule
  # OR
  plug MyApp.AuthPipeline, key: :impersonate
  ```

  ### Options

  You can provide options to the pipeline when you `use Guardian.Plug.Pipeline`
  or you can provide them when you call the plug.

  Additionally, for every option other than `:otp_app` you can use elixir
  configuration, the using options, or linline options.

  * `:otp_app` - The otp app where the pipeline modules can be found
  * `:module` - The `Guardian` implementation module
  * `:error_handler` - An error handling module. See `Guardian.Plug.Errors`
  * `:key` - The key to use

  ### Keys

  Using keys allows you to specifiy locations in the session/connection where
  the tokens and resources will be placed. This allows multiple authenticated
  tokens to be in play for a single request. This is useful for impersonation or
  higher security areas where you can have a specific set of privilages and
  still be logged in.

  ### Error handler

  When using plugs, you'll need to specify an error handler

  The error_handler requires an `auth_error` function that receives the conn
  and the error reason

  ### Inline pipelines

  If you want to define your pipeline inline, you can do so by using
  `Guardian.Plug.Pipeline` as a plug itself.
  You _must_ supply the module and error handler inline if you do this.

  ```elixir
  plug Guardian.Plug.Pipeline, module: MyApp.Tokens,
                          error_handler: MyApp.AuthErrorHandler
  plug Guardian.VerifyHeader, realm: "Bearer"
  ```

  Inline pipelines are also good to change the error handler that you want to use.

  Note that you must set the pipeline before using other guardian plugs.

  ```elixir
  # Use the MyApp.AuthErrorHandler for downstream Guardian plugs
  plug Guardian.Plug.Pipeline, module: MyApp.Tokens,
                          error_handler: MyApp.AuthErrorHandler
  plug Guardian.VerifyHeader, realm: "Bearer"

  # Now change out the error handler for plugs downstream of this one.
  plug Guardian.Plug.Pipeline, error_handler: MyApp.SpecialAuthErrorHandler
  ```
  """

  import Plug.Conn

  @doc """
  Create your very own `Guardian.Plug.Pipeline`

  Using this macro will make your module into a plug builder.
  It will provide your pipeline with the Guardian implementation module and error
  handler so that it can be used within your pipeline and downstream.
  """
  defmacro __using__(opts \\ []) do
    quote do
      use Plug.Builder
      import Guardian.Plug.Pipeline

      def init(opts) do
        otp_app = Keyword.get(opts, :otp_app) ||
          Keyword.get(unquote(opts), :otp_app)
        if !otp_app do
          raise ":otp_app not specified by #{to_string(__MODULE__)}"
        end

        config = Application.get_env(otp_app, __MODULE__) || []

        new_opts =
          config
          |> Keyword.merge(unquote(opts))
          |> Keyword.merge(opts)

        module = Keyword.get(new_opts, :module)
        error = Keyword.get(new_opts, :error_handler)

        if !module, do: raise ":module not specified for #{to_string(__MODULE__)}"
        if !error, do: raise ":error_handler not specified for #{to_string(__MODULE__)}"

        new_opts
      end

      plug :put_modules

      defp put_modules(conn, opts) do
        alias Guardian.Plug, as: GPlug
        alias GPlug.{Pipeline}

        pipeline_opts = Keyword.take(opts, [:module, :error_handler, :key])
        Pipeline.call(conn, pipeline_opts)
      end
    end
  end

  def call(conn, opts) do
    conn
    |> maybe_set_item(:guardian_module, Keyword.get(opts, :module))
    |> maybe_set_item(
      :guardian_error_handler,
      Keyword.get(opts, :error_handler)
    )
    |> maybe_set_item(:guardian_key, Keyword.get(opts, :key))
  end

  def set_key(conn, key) do
    put_private(conn, :guardian_key, key)
  end

  def set_module(conn, module) do
    put_private(conn, :guardian_module, module)
  end

  def set_error_handler(conn, module) do
    put_private(conn, :guardian_error_handler, module)
  end

  def current_key(conn), do: conn.private[:guardian_key]
  def current_module(conn), do: conn.private[:guardian_module]
  def current_error_handler(conn), do: conn.private[:guardian_error_handler]

  defp maybe_set_item(conn, _key, nil), do: conn
  defp maybe_set_item(conn, key, val), do: put_private(conn, key, val)
end
