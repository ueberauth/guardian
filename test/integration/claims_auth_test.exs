defmodule Guardian.Integration.ClaimsAuthTest do
  @moduledoc false
  use ExUnit.Case
  use Plug.Test

  import Guardian.TestHelper

  alias Guardian.Plug.LoadResource
  alias Guardian.Plug.VerifyClaims
  alias Guardian.Claims

  defmodule TestSerializer do
    @moduledoc false
    @behaviour Guardian.Serializer

    def from_token("Company:" <> id), do: {:ok, id}
    def for_token(_), do: {:ok, nil}
  end

  test "load current resource with a valid jwt in session" do
    claims = Claims.app_claims(%{"sub" => "Company:42", "aud" => "aud"})

    conn = conn(:get, "/")

    conn =
      conn
      |> conn_with_fetched_session
      |> put_session(Guardian.Keys.base_key(:default), claims)
      |> run_plug(VerifyClaims)
      |> run_plug(LoadResource, serializer: TestSerializer)

    assert Guardian.Plug.current_resource(conn) == "42"
    assert Guardian.Plug.claims(conn) == {:ok, claims}
  end
end
