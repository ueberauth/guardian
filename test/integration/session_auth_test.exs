defmodule Guardian.Integration.SessionAuthTest do
  @moduledoc false
  use ExUnit.Case
  # use Plug.Test
  #
  # #import Guardian.TestHelper
  #
  # alias Guardian.Plug.LoadResource
  # alias Guardian.Plug.VerifySession
  # alias Guardian.Claims
  #
  # defmodule TestSerializer do
  #   @moduledoc false
  #   @behaviour Guardian.Serializer
  #
  #   def from_token("Company:" <> id), do: {:ok, id}
  #   def for_token(_), do: {:ok, nil}
  # end
  #
  # @skip "TODO"
  # test "load current resource with a valid jwt in session" do
  #   claims = Claims.app_claims(%{"sub" => "Company:42", "aud" => "aud"})
  #   jwt = build_jwt(claims)
  #
  #   conn = conn(:get, "/")
  #
  #   conn =
  #     conn
  #     |> conn_with_fetched_session
  #     |> put_session(Guardian.Keys.base_key(:default), jwt)
  #     |> run_plug(VerifySession)
  #     |> run_plug(LoadResource, serializer: TestSerializer)
  #
  #   assert Guardian.Plug.current_resource(conn) == "42"
  #   assert Guardian.Plug.claims(conn) == {:ok, claims}
  #   assert Guardian.Plug.current_token(conn) == jwt
  # end
end
