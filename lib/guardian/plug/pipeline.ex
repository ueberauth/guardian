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
    alias Guardian.Plug.Pipeline

    quote do
      use Plug.Builder

      import Pipeline

      plug :put_modules

      def init(options) do
        new_opts =
          options
          |> Keyword.merge(unquote(opts))
          |> app_config

        unless Keyword.has_key?(new_opts, :module),
          do: raise_error(:module)

        unless Keyword.has_key?(new_opts, :error_handler),
          do: raise_error(:error_handler)

        new_opts
      end

      defp app_config(opts) do
        case Keyword.get(opts, :otp_app) do
          nil -> opts
          otp_app -> Application.get_env(otp_app, __MODULE__) ++ opts
        end
      end

      defp put_modules(conn, opts) do
        pipeline_opts = Keyword.take(opts, [:module, :error_handler, :key])
        Pipeline.call(conn, pipeline_opts)
      end

      defp raise_error(key),
        do: raise "Config `#{key}` is missing for #{__MODULE__}"
    end
  end

  def call(conn, opts) do
    [module, error_handler, key] =
      opts
      |> Keyword.take([:module, :error_handler, :key])
      |> Keyword.values

    conn
    |> put_module(module)
    |> put_error_handler(error_handler)
    |> put_key(key)
  end

  def put_key(conn, key),
    do: put_private(conn, :guardian_key, key)

  def put_module(conn, module),
    do: put_private(conn, :guardian_module, module)

  def put_error_handler(conn, module),
    do: put_private(conn, :guardian_error_handler, module)

  def current_key(conn), do: conn.private[:guardian_key]
  def current_module(conn), do: conn.private[:guardian_module]
  def current_error_handler(conn), do: conn.private[:guardian_error_handler]
end
