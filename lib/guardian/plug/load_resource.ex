defmodule Guardian.Plug.LoadResource do
  @moduledoc """
  Fetches the resource specified in a set of claims.

  The current resource is loaded by calling `from_token/1` on your
  `Guardian.Serializer` with the value of the `sub` claim. See the `:serializer`
  option for more details.

  If the resource is loaded successfully, it is accessible by calling
  `Guardian.Plug.current_resource/2`.

  If there is no valid JWT in the request so far (`Guardian.Plug.VerifySession`
  / `Guardian.Plug.VerifyHeader`) did not find a valid token
  then nothing will occur, and `Guardian.Plug.current_resource/2` will be nil.

  ## Options

    * `:serializer` - The serializer to use to load the current resource from
        the subject claim of the token. Defaults to the result of
        `Guardian.serializer/0`.

    * `:claim` - The claim to look for to pass value to serializer. Defaults to `sub`.
  """

  @doc false
  def init(opts \\ %{}), do: Enum.into(opts, %{})

  @doc false
  def call(conn, opts) do
    key = Map.get(opts, :key, :default)

    case Guardian.Plug.current_resource(conn, key) do
      nil ->
        case Guardian.Plug.claims(conn, key) do
          {:ok, claims} ->
            claims |> load_resource(opts) |> put_current_resource(conn, key)
          {:error, _} -> Guardian.Plug.set_current_resource(conn, nil, key)
        end
      _ -> conn
    end
  end

  defp put_current_resource({:ok, resource}, conn, key) do
    Guardian.Plug.set_current_resource(conn, resource, key)
  end

  defp put_current_resource({:error, _}, conn, key) do
    Guardian.Plug.set_current_resource(conn, nil, key)
  end

  defp load_resource(claims, opts) do
    serializer = get_serializer(opts)
    resource_claim = Map.get(opts, :claim, "sub")

    claims
    |> Map.get(resource_claim)
    |> serializer.from_token()
  end

  defp get_serializer(opts) do
    Map.get(opts, :serializer, Guardian.serializer)
  end
end
