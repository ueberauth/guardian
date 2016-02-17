defmodule Guardian.Plug.BackdoorTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Plug.Test
  import Guardian.TestHelper

  test "sets the current resource with the default serializer" do
    conn = conn(:get, "/?as=User:15")

    current_resource =
      conn
      |> conn_with_fetched_session
      |> run_plug(Guardian.Plug.Backdoor)
      |> Guardian.Plug.current_resource

    {:ok, deserialized_resource} = Guardian.serializer.from_token("User:15")
    assert current_resource == deserialized_resource
  end

  defmodule SampleSerializer do
    @moduledoc false
    @behaviour Guardian.Serializer

    def from_token("User:" <> user_id) do
      {:ok, %{id: user_id}}
    end
    def from_token(token) do
      {:error, "Unable to find resource for token: '#{token}'."}
    end

    def for_token(%{id: user_id}) do
      {:ok, "User:" <> user_id}
    end
  end

  test "sets the current resource with the given serializer" do
    conn = conn(:get, "/?as=User:15")

    current_resource = conn
      |> conn_with_fetched_session
      |> run_plug(Guardian.Plug.Backdoor, serializer: SampleSerializer)
      |> Guardian.Plug.current_resource

    {:ok, deserialized_resource} = SampleSerializer.from_token("User:15")
    assert current_resource == deserialized_resource
  end

  test "allows the backdoor param to be overridden" do
    conn = conn(:get, "/?impersonate=User:15")

    current_resource =
      conn
      |> conn_with_fetched_session
      |> run_plug(Guardian.Plug.Backdoor, serializer: SampleSerializer,
          param_name: "impersonate")
      |> Guardian.Plug.current_resource

    {:ok, deserialized_resource} = SampleSerializer.from_token("User:15")
    assert current_resource == deserialized_resource
  end

  test "does nothing if the param is not given" do
    conn = conn(:get, "/")

    conn =
      conn
      |> conn_with_fetched_session
      |> run_plug(Guardian.Plug.Backdoor, serializer: SampleSerializer)

    current_resource = Guardian.Plug.current_resource(conn)

    assert current_resource == nil
    refute Guardian.Plug.authenticated?(conn)
    refute conn.halted
  end

  test "halts and returns an error when the serializer can't find the object" do
    conn = conn(:get, "/?as=invalid")

    conn =
      conn
      |> conn_with_fetched_session
      |> run_plug(Guardian.Plug.Backdoor, serializer: SampleSerializer)

    {status, _, _body} = sent_resp(conn)

    assert status == 500
    assert conn.halted
  end
end
