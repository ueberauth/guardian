defmodule Guardian.Plug.Test.Backdoor do
  @moduledoc """
  This plug allows you to bypass authentication in acceptance tests
  by passing the token needed to load the current resource directly to your
  serializer, via a query string parameter.

  ## Installation

  Add the following to your Phoenix router before any other Guardian plugs.

  ```
  plug Guardian.Plug.Test.Backdoor
  plug Guardian.Plug.VerifySession
  ```

  ***This plug is designed for acceptance testing scenarios and should
  never be added in a production environment.***

  ## Usage

  Now that `Guardian.Plug.Backdoor` is installed, it's time to log in.
  If you're using [Hound][hound], you can write the following code.

  ```
  {:ok, token, _} = Guardian.encode_and_sign(user, :access, new_claims)
  navigate_to "/?token=\#{token}"
  ```

  If you aren't using [Hound][hound], a simple `GET /?as=User:5` request will
  work.

  When the `Guardian.Plug.Test.Backdoor` plug runs, it passes along the value
  of the `as` parameter directly to your application's Guardian serializer.

  ## Options

  The following options can be set when instantiating the plug.

  * `token_field` - Query string field used to load the current resource.
    Defaults to `token`.

  [hound]: https://github.com/HashNuke/hound
  """
  import Plug.Conn

  @doc false
  def init(opts \\ []) do
    serializer = Keyword.get(opts, :serializer, Guardian.serializer())
    token_field = Keyword.get(opts, :token_field, "token")

    %{
      serializer: serializer,
      token_field: token_field,
    }
  end

  @doc false
  if Mix.env() == :prod do
    def call(conn, _opts), do: conn
  else
    def call(conn, %{token_field: token_field} = opts) do
      case get_backdoor_token(conn, token_field) do
        nil ->
          conn
        backdoor_token ->
          handle_backdoor_token(conn, backdoor_token, opts)
      end
    end

    defp get_backdoor_token(conn, token_field) do
      conn
      |> fetch_query_params()
      |> Map.get(:params)
      |> Map.get(token_field)
    end

    defp handle_backdoor_token(conn, encoded_token, %{serializer: serializer}) do
      with {:ok, claims} <- Guardian.decode_and_verify(encoded_token),
           %{"sub" => decoded_token, "typ" => type} <- claims,
           {:ok, resource} <- serializer.from_token(decoded_token) do
        Guardian.Plug.sign_in(conn, resource, type)
      else
        {:error, _reason} ->
          conn
          |> send_resp(500, "Guardian.Plug.Test.Backdoor plug cannot " <>
          "deserialize \"#{encoded_token}\" with #{serializer}")
          |> halt()
      end
    end
  end
end
