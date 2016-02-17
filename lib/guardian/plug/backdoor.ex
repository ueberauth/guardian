defmodule Guardian.Plug.Backdoor do
  @moduledoc """
  This plug allows you to bypass authentication in acceptance tests
  by passing the token needed to load the current resource directly to your
  serializer, via a query string parameter.

  ## Installation

  Add the following to your Phoenix router before any other Guardian plugs.

  ```
  if Mix.env == :test do
    plug Guardian.Plug.Backdoor
  end
  ```

  ***This plug is designed for acceptance testing scenarios and should
  never be added in a production environment.***

  ## Usage

  Now that `Guardian.Plug.Backdoor` is installed, it's time to log in.
  If you're using [Hound][hound], you can write the following code.

  ```
  navigate_to "/?as=User:5"
  ```

  If you aren't using [Hound][hound], a simple `GET /?as=User:5` request will
  work.

  When the `Guardian.Plug.Backdoor` plug runs, it passes along the value
  of the `as` parameter directly to your application's Guardian serializer.

  ```
  defmodule MyGuardianSerializer do
    @behaviour Guardian.Serializer

    def from_token("User:" <> user_id) do
      # Find and return the user object
      {:ok, %{id: user_id}}
    end
    def from_token(_token) do
      {:error, "Invalid token"}
    end

    def for_token(user) do
      # Serialize the user into a single token
    end
  end
  ```

  In this example, all further requests will be made as User 5.

  ## Options

  The following options can be set when instantiating the plug.

  * `param_name` - The query string parameter that is used to load the
    current resource. Defaults to `as`.
  * `serializer` - The serializer to be used to load the current
    resource. Defaults to the serializer configured in your app's
    Guardian config.


  [hound]: https://github.com/HashNuke/hound
  """
  import Plug.Conn

  @doc false
  def init(opts \\ %{}) do
    opts = Enum.into(opts, %{})

    serializer = Map.get(opts, :serializer, Guardian.serializer)
    param_name = Map.get(opts, :param_name, "as")

    %{
      serializer: serializer,
      param_name: param_name
    }
  end

  @doc false
  def call(conn, %{serializer: serializer, param_name: param_name}) do
    resource_token = get_backdoor_param_value(conn, param_name)

    if resource_token do
      conn = case load_resource(resource_token, serializer) do
        {:ok, obj} -> Guardian.Plug.sign_in(conn, obj)
        {:error, reason} -> handle_error(conn, reason, param_name)
      end
    end

    conn
  end

  defp load_resource(token, serializer) do
    serializer.from_token(token)
  end

  defp get_backdoor_param_value(conn, param_name) do
    conn
    |> fetch_query_params
    |> Map.get(:params)
    |> Map.get(param_name)
  end

  defp handle_error(conn, reason, param_name) do
    conn
    |> send_resp(500,
      "Error while decoding \"#{param_name}\" parameter with the " <>
      "Guardian.Plug.Backdoor plug:\n#{reason}")
    |> halt
  end
end
