defmodule Guardian.Phoenix.ChannelTest.Endpoint do
  @moduledoc false
  use Phoenix.Endpoint, otp_app: :guardian
end

defmodule Guardian.Phoenix.ChannelTest.Impl do
  @moduledoc false
  use Guardian, otp_app: :guardian,
                issuer: "Me",
                secret_key: "some-secret"

  def subject_for_token(%{id: id}, _claims), do: {:ok, to_string(id)}
  def resource_from_claims(%{"sub" => id}), do: {:ok, %{id: id}}
end

defmodule Guardian.Phoenix.ChannelTest.MyChannel do
  @moduledoc false
  use Phoenix.Channel
  use Guardian.Phoenix.Channel, module: Guardian.Phoenix.ChannelTest.Impl

  def join(_room, params, socket), do: {:ok, params, socket}
end
