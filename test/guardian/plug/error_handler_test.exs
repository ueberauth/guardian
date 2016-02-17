defmodule Guardian.Plug.ErrorHandlerTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Plug.Test

  alias Guardian.Plug.ErrorHandler

  setup do
    conn = conn(:get, "/foo")
    {:ok, %{conn: conn}}
  end

  test "unauthenticated/2 sends a 401 response when text/html", %{conn: conn} do
    conn = put_req_header(conn, "accept", "text/html")

    {status, headers, body} =
      conn
      |> ErrorHandler.unauthenticated(%{})
      |> sent_resp

    assert status == 401
    assert content_type(headers) == "text/plain"
    assert body == "Unauthenticated"
  end

  test "unauthenticated/2 sends a 401 response when json", %{conn: conn} do
    conn = put_req_header(conn, "accept", "application/json")

    {status, headers, body} =
      conn
      |> ErrorHandler.unauthenticated(%{})
      |> sent_resp

    assert status == 401
    assert content_type(headers) == "application/json"
    assert body ==  Poison.encode!(%{errors: ["Unauthenticated"]})
  end

  test "unauthenticated/2 when no accept header", %{conn: conn} do
    {status, headers, body} =
      conn
      |> ErrorHandler.unauthenticated(%{})
      |> sent_resp

    assert status == 401
    assert content_type(headers) == "text/plain"
    assert body ==  "Unauthenticated"
  end

  test "unauthorized/2 sends a 403 response when text/html", %{conn: conn} do
    conn = put_req_header(conn, "accept", "text/html")

    {status, headers, body} =
      conn
      |> ErrorHandler.unauthorized(%{})
      |> sent_resp

    assert status == 403
    assert content_type(headers) == "text/plain"
    assert body == "Unauthorized"
  end

  test "unauthorized/2 sends a 403 response when json", %{conn: conn} do
    conn = put_req_header(conn, "accept", "application/json")

    {status, headers, body} =
      conn
      |> ErrorHandler.unauthorized(%{})
      |> sent_resp

    assert status == 403
    assert content_type(headers) == "application/json"
    assert body ==  Poison.encode!(%{errors: ["Unauthorized"]})
  end

  test "unauthorized/2 sends 403 resp when no accept header", %{conn: conn} do
    {status, headers, body} =
      conn
      |> ErrorHandler.unauthorized(%{})
      |> sent_resp

    assert status == 403
    assert content_type(headers) == "text/plain"
    assert body == "Unauthorized"
  end

  test "already_authenticated/2 halt the conn", %{conn: conn} do
    conn = conn
           |> ErrorHandler.already_authenticated(%{})
    assert conn.halted
  end

  defp content_type(headers) do
    {:ok, type, subtype, _params} =
      headers
        |> header_value("content-type")
        |> Plug.Conn.Utils.content_type
    "#{type}/#{subtype}"
  end

  defp header_value(headers, key) do
    headers
    |> Enum.filter(fn({k, _}) -> k == key end)
    |> Enum.map(fn({_, v}) -> v end)
    |> List.first
  end
end
