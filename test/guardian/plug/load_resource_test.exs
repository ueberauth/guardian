defmodule Guardian.Plug.LoadResourceTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Plug.Test
  import Guardian.TestHelper

  alias Guardian.Plug.LoadResource

  setup do
    conn = conn_with_fetched_session(conn(:get, "/"))
    {:ok, %{conn: conn}}
  end

  test "with a resource already set", %{conn: conn} do
    conn = conn
    |> Guardian.Plug.set_current_resource(:the_resource)
    |> run_plug(LoadResource)
    assert Guardian.Plug.current_resource(conn) == :the_resource
  end

  test "with no resource set and no claims", %{conn: conn} do
    conn = run_plug(conn, LoadResource)
    assert Guardian.Plug.current_resource(conn) == nil
  end

  test "with no resource set and erroneous claims", %{conn: conn} do
    conn = conn
    |> Guardian.Plug.set_claims({:error, :some_error})
    |> run_plug(LoadResource)
    assert Guardian.Plug.current_resource(conn) == nil
  end

  test "with no resource set and valid claims", %{conn: conn} do
    conn = conn
    |> Guardian.Plug.set_claims({:ok, %{"sub" => "User:42"}})
    |> run_plug(LoadResource)
    assert Guardian.Plug.current_resource(conn) == "User:42"
  end
end
