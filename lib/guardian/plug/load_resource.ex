defmodule Guardian.Plug.LoadResource do
  @moduledoc """
  Fetches the resource specified in a set of claims.

  The Guardian.serializer/0 is used once the subject is extracted from the token.

  The resource becomes available at Guardian.Plug.current_resource(conn) if successful.

  If there is no valid JWT in the request so far (Guardian.Plug.VerifySession / Guardian.Plug.VerifyAuthorization) did not find a valid token
  then nothing will occur, and the Guardian.Plug.current_resource/1 will be nil
  """

  @doc false
  def init(opts \\ %{}), do: Enum.into(opts, %{})

  @doc false
  def call(conn, opts) do
    key = Dict.get(opts, :key, :default)

    case Guardian.Plug.current_resource(conn, key) do
      { :ok, _ } -> conn
      { :error, _ } -> conn
      _ ->
        case Guardian.Plug.claims(conn, key) do
          { :ok, claims } ->
            case Guardian.serializer.from_token(Dict.get(claims, "sub")) do
              { :ok, resource } -> Guardian.Plug.set_current_resource(conn, resource, key)
              { :error, _ } -> Guardian.Plug.set_current_resource(conn, nil, key)
            end
          { :error, _ } -> Guardian.Plug.set_current_resource(conn, nil, key)
          _ -> Guardian.Plug.set_current_resource(conn, nil, key)
        end
    end
  end
end
