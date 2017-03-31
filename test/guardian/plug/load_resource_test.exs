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

  test "with no resource set, valid claims, default serializer", %{conn: conn} do
    sub =  "User:42"

    conn = conn
    |> Guardian.Plug.set_claims({:ok, %{"sub" => sub}})
    |> run_plug(LoadResource)

    {:ok, resource} = Guardian.serializer.from_token(sub)
    assert Guardian.Plug.current_resource(conn) == resource
  end

  test "with valid claims and custom serializer", %{conn: conn} do
    defmodule TestSerializer do
      @moduledoc false
      @behaviour Guardian.Serializer

      def from_token("User:" <> id), do: {:ok, id}
      def for_token(_), do: {:ok, nil}
    end

    conn = conn
    |> Guardian.Plug.set_claims({:ok, %{"sub" => "User:42"}})
    |> run_plug(LoadResource, serializer: TestSerializer)
    assert Guardian.Plug.current_resource(conn) == "42"
  end

  test "claim option specified, but not found", %{conn: conn} do
    sub =  "User:42"

    conn = conn
    |> Guardian.Plug.set_claims({:ok, %{"sub" => sub}})
    |> run_plug(LoadResource, claim: "user")

    assert Guardian.Plug.current_resource(conn) == nil
  end

  test "claim option specified, and is found", %{conn: conn} do
    sub =  "User:42"

    conn = conn
    |> Guardian.Plug.set_claims({:ok, %{"user" => sub}})
    |> run_plug(LoadResource, claim: "user")

    {:ok, resource} = Guardian.serializer.from_token(sub)
    assert Guardian.Plug.current_resource(conn) == resource
  end
end
