defmodule Guardian.CSRFProtection do
  @moduledoc false
  alias Plug.Crypto.KeyGenerator
  alias Plug.Crypto.MessageEncryptor

  if !Guardian.config(:secret_key), do: raise "Guardian requires a secret_key"

  @doc false
  def signature(nil), do: nil
  @doc false
  def signature(csrf_token), do: sign(csrf_token)

  @doc false
  def verify(nil, nil), do: false
  @doc false
  def verify(signed_csrf, nil), do: false
  @doc false
  def verify(signed_csrf, expected_csrf), do: sign(expected_csrf) == signed_csrf

  @doc false
  defp sign(string) do
    secret = Guardian.config(:secret_key)
    :crypto.hmac(:sha256, secret, string) |> Base.url_encode64 |> String.rstrip(?=)
  end

  @doc false
  def csrf_from_header(conn), do: List.first(Plug.Conn.get_req_header(conn, "x-csrf-token") || [])
  @doc false
  def csrf_from_params(conn), do: Dict.get(conn.params, "_csrf_token")
  @doc false
  def csrf_from_session(conn), do: Plug.CSRFProtection.get_csrf_token
end
