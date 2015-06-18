defmodule Guardian.CSRFProtection do
  alias Plug.Crypto.KeyGenerator
  alias Plug.Crypto.MessageEncryptor

  if !Guardian.config(:secret_key), do: raise "Guardian requires a secret_key"

  def signature(csrf_token), do: sign(csrf_token)

  def verify(nil, nil), do: false
  def verify(signed_csrf, nil), do: false
  def verify(signed_csrf, expected_csrf), do: sign(expected_csrf) == signed_csrf

  defp sign(string) do
    secret = Guardian.config(:secret_key)
    :crypto.hmac(:sha256, secret, string) |> Base.url_encode64 |> String.rstrip(?=)
  end

  def csrf_from_header(conn), do: List.first(Plug.Conn.get_req_header(conn, "x-csrf-token") || [])
  def csrf_from_params(conn), do: Dict.get(conn.params, "_csrf_token")
  def csrf_from_session(conn), do: Plug.CSRFProtection.get_csrf_token
end
