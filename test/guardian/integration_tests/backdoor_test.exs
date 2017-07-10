defmodule Guardian.IntegrationTests.BackdoorTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Plug.Test
  import Guardian.TestHelper

  defmodule SampleSerializer do
    @moduledoc false
    @behaviour Guardian.Serializer

    def from_token("User:" <> user_id) do
      {:ok, %{id: user_id}}
    end
    def from_token(token) do
      {:error, "Invalid token #{token}"}
    end

    def for_token(%{id: user_id}) do
      {:ok, "User:" <> user_id}
    end
  end

  # Created a pipeline so plug can actually run through the compilation steps
  # and report any invalid init methods when compiling
  defmodule BackdoorVerifySessionPipeline do
    @moduledoc false
    use Plug.Builder

    plug Guardian.Plug.Backdoor, serializer: SampleSerializer
    plug Guardian.Plug.VerifySession
    plug Guardian.Plug.LoadResource
  end

  test "request with backdoor token set to exactly what serializer expects" do
    conn = conn(:get, "/?as=User:15")

    conn =
      conn
      |> conn_with_fetched_session
      |> BackdoorVerifySessionPipeline.call(%{})

    resource = Guardian.Plug.current_resource(conn)

    assert resource == %{id: "15"}
    assert Guardian.Plug.authenticated?(conn)
  end

  test "request with backdoor token set to something unexpected" do
    conn = conn(:get, "/?as=invalid")

    conn =
      conn
      |> conn_with_fetched_session
      |> BackdoorVerifySessionPipeline.call(%{})

    refute Guardian.Plug.current_resource(conn)
    refute Guardian.Plug.authenticated?(conn)
  end

  test "request without as parameter set" do
    conn = conn(:get, "/")

    conn =
      conn
      |> conn_with_fetched_session
      |> BackdoorVerifySessionPipeline.call(%{})

    refute Guardian.Plug.current_resource(conn)
    refute Guardian.Plug.authenticated?(conn)
  end

  defmodule BackdoorVerifyHeaderPipeline do
    @moduledoc false
    use Plug.Builder

    plug Guardian.Plug.Backdoor, serializer: SampleSerializer
    plug Guardian.Plug.VerifyHeader
    plug Guardian.Plug.LoadResource
  end

  test "VerifyHeader request with backdoor token set to exactly what serializer expects" do
    conn = conn(:get, "/?as=User:15")

    conn =
      conn
      |> conn_with_fetched_session
      |> BackdoorVerifyHeaderPipeline.call(%{})

    resource = Guardian.Plug.current_resource(conn)

    assert resource == %{id: "15"}
    assert Guardian.Plug.authenticated?(conn)
  end
end
