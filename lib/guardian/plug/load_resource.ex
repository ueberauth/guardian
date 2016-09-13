defmodule Guardian.Plug.LoadResource do
  @moduledoc """
  Fetches the resource specified in a set of claims.

  The `Guardian.serializer/0` is used
  once the subject is extracted from the token.

  The resource becomes available at `Guardian.Plug.current_resource(conn)`
  if successful.

  If there is no valid JWT in the request so far (Guardian.Plug.VerifySession /
  Guardian.Plug.VerifyHeader) did not find a valid token
  then nothing will occur, and the Guardian.Plug.current_resource/1 will be nil
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
            result = Guardian.serializer.from_token(Map.get(claims, "sub"))
            set_current_resource_from_serializer(conn, key, result)
          {:error, _} -> Guardian.Plug.set_current_resource(conn, nil, key)
        end
      _ -> conn
    end
  end

  defp set_current_resource_from_serializer(conn, key, {:ok, resource}) do
    Guardian.Plug.set_current_resource(conn, resource, key)
  end

  defp set_current_resource_from_serializer(conn, key, {:error, _}) do
    Guardian.Plug.set_current_resource(conn, nil, key)
  end
end
