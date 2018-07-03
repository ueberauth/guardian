defmodule Guardian.Phoenix.SocketTest.Endpoint do
  @moduledoc false
  use Phoenix.Endpoint, otp_app: :guardian
end

defmodule Guardian.Phoenix.SocketTest.Impl do
  @moduledoc false
  use Guardian,
    otp_app: :guardian,
    issuer: "Me",
    secret_key: "some-secret"

  def subject_for_token(%{id: id}, _claims), do: {:ok, to_string(id)}
  def resource_from_claims(%{"sub" => id}), do: {:ok, %{id: id}}
end

defmodule Guardian.Phoenix.SocketTest.MySocket do
  @moduledoc false
  use Phoenix.Socket
  import Guardian.Phoenix.Socket
  alias Guardian.Phoenix.SocketTest.Impl

  def connect(%{"guardian_token" => token}, socket) do
    case authenticate(socket, Impl, token) do
      {:ok, authed_socket} -> {:ok, authed_socket}
      _ -> :error
    end
  end

  def connect(_params, _socket), do: :error

  def id(_), do: Guardian.UUID.generate()
end
