defmodule Guardian.Plug.ErrorHandler do
  @callback unauthenticated(Plug.t, Map.t) :: Plug.t
  @callback unauthorized(Plug.t, Map.t) :: Plug.t

  import Plug.Conn

  def unauthenticated(conn, _params) do
    respond(conn, accept_type(conn), 401, "Unauthenticated")
  end

  def unauthorized(conn, _params) do
    respond(conn, accept_type(conn), 403, "Unauthorized")
  end

  defp respond(conn, :json, status, msg) do
    try do
      conn
      |> configure_session(drop: true)
      |> put_resp_content_type("application/json")
      |> send_resp(status, Poison.encode!(%{errors: [msg]}))
    rescue ArgumentError ->
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(status, Poison.encode!(%{errors: [msg]}))
    end
  end

  defp respond(conn, :html, status, msg) do
    try do
      conn
      |> configure_session(drop: true)
      |> put_resp_content_type("text/plain")
      |> send_resp(status, msg)
    rescue ArgumentError ->
      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(status, msg)
    end
  end

  defp accept_type(conn) do
    accept = conn
    |> get_req_header("accept")
    |> List.wrap
    |> hd

    cond do
      Regex.match?(~r/json/, accept) -> :json
      true -> :html
    end
  end
end
