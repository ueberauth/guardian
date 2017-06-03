defmodule Guardian.Phoenix.ControllerTest.Router do
  @moduledoc false
  use Phoenix.Router

  get "/things", Guardian.Phoenix.ControllerTest.TestController, :things
end

defmodule Guardian.Phoenix.ControllerTest.TestController do
  @moduledoc false
  use Phoenix.Controller, namespace: Guardian.Phoenix.ControllerTest
  use Guardian.Phoenix.Controller, module: Guardian.Phoenix.ControllerTest.Impl
  import Plug.Conn

  def things(conn, _params, resource, claims) do
    resp = %{resource: resource, claims: claims}

    conn
    |> put_status(200)
    |> json(resp)
  end
end

defmodule Guardian.Phoenix.ControllerTest.Impl do
  @moduledoc false
  use Guardian, otp_app: :guardian,
                issuer: "Me",
                secret_key: "some-secret"

  def subject_for_token(%{id: id}, _claims), do: {:ok, to_string(id)}
  def resource_from_claims(%{"sub" => id}), do: {:ok, %{id: id}}
end
