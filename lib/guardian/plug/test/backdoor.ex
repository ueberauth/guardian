defmodule Guardian.Plug.Test.Backdoor do
  @moduledoc """
  This plug allows you to bypass authentication in acceptance tests
  by passing the token needed to load the current resource directly to your
  serializer, via a query string parameter.

  ## Installation

  Add the following to your Phoenix router before any other Guardian plugs.

  ```
  if Mix.env == :test do
    plug Guardian.Plug.Test.Backdoor
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

  When the `Guardian.Plug.Test.Backdoor` plug runs, it passes along the value
  of the `as` parameter directly to your application's Guardian serializer.

  ## Options

  The following options can be set when instantiating the plug.

  * `serializer` - The serializer to be used to load the current resource.
    Defaults to the serializer configured in your app's Guardian config.
  * `token_field` - Query string field used to load the current resource.
    Defaults to `as`.
  * `type` - Type of token, passed directly to Guardian.Plug.sign_in/4.
  * `new_claims` - New claims to be encoded in the JWT, passed directly to
    Guardian.Plug.sign_in/4.

  [hound]: https://github.com/HashNuke/hound
  """
  import Plug.Conn

  @doc false
  def init(opts \\ []) do
    serializer = Keyword.get(opts, :serializer, Guardian.serializer())
    token_field = Keyword.get(opts, :token_field, "as")
    type = Keyword.get(opts, :type)
    new_claims = Keyword.get(opts, :new_claims, [])

    %{
      serializer: serializer,
      token_field: token_field,
      type: type,
      new_claims: new_claims,
    }
  end

  @doc false
  def call(conn, %{token_field: token_field} = opts) do
    case get_backdoor_token(conn, token_field) do
      nil ->
        conn
      backdoor_token ->
        handle_backdoor_token(conn, backdoor_token, opts)
    end
  end

  defp handle_backdoor_token(conn, token,
       %{serializer: serializer, type: type, new_claims: new_claims}) do
    case serializer.from_token(token) do
      {:ok, resource} ->
        Guardian.Plug.sign_in(conn, resource, type, new_claims)
      {:error, reason} ->
        conn
        |> send_resp(500, "Guardian.Plug.Backdoor plug cannot deserialize " <>
        "\"#{token}\" with #{serializer}:\n#{reason}")
        |> halt()
    end
  end

  defp get_backdoor_token(conn, token_field) do
    conn
    |> fetch_query_params()
    |> Map.get(:params)
    |> Map.get(token_field)
  end
end
