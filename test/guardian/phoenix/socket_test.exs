defmodule Guardian.Phoenix.SocketTest do
  use ExUnit.Case, async: true

  alias Guardian.Phoenix.Socket, as: GuardianSocket

  defmodule TestSocket do
    defstruct assigns: %{}
  end

  setup do
    claims = %{
      "aud" => "User:1",
      "typ" => "token",
      "exp" => Guardian.Utils.timestamp + 100_00,
      "iat" => Guardian.Utils.timestamp,
      "iss" => "MyApp",
      "sub" => "User:1",
      "something_else" => "foo"}

    config = Application.get_env(:guardian, Guardian)
    algo = hd(Keyword.get(config, :allowed_algos))
    secret = Keyword.get(config, :secret_key)

    jose_jws = %{"alg" => algo}
    jose_jwk = %{"kty" => "oct", "k" => :base64url.encode(secret)}

    { _, jwt } = JOSE.JWT.sign(jose_jwk, jose_jws, claims) |> JOSE.JWS.compact

    { :ok, %{
        socket: %TestSocket{},
        claims: claims,
        jwt: jwt,
        jose_jws: jose_jws,
        jose_jwk: jose_jwk
      }
    }
  end

  test "current_claims from socket", %{socket: socket} do
    key = Guardian.Keys.claims_key
    assigns = %{key => %{"the" => "claims"}}
    socket = Map.put(socket, :assigns, assigns)
    assert GuardianSocket.current_claims(socket) == %{"the" => "claims"}
  end

  test "current_claims from socket in secret location", %{socket: socket} do
    key = Guardian.Keys.claims_key(:secret)
    assigns = %{key => %{"the" => "claims"}}
    socket = Map.put(socket, :assigns, assigns)
    assert GuardianSocket.current_claims(socket, :secret) == %{"the" => "claims"}
  end

  test "current_token from socket", %{socket: socket} do
    key = Guardian.Keys.jwt_key
    assigns = %{key => "THE JWT"}
    socket = Map.put(socket, :assigns, assigns)
    assert GuardianSocket.current_token(socket) == "THE JWT"
  end

  test "current_token from socket secret location", %{socket: socket} do
    key = Guardian.Keys.jwt_key(:secret)
    assigns = %{key => "THE JWT"}
    socket = Map.put(socket, :assigns, assigns)
    assert GuardianSocket.current_token(socket, :secret) == "THE JWT"
  end

  test "fetches the serialized sub from the token for current_resource", %{socket: socket, claims: claims} do
    key = Guardian.Keys.claims_key
    assigns = %{key => claims}
    socket = Map.put(socket, :assigns, assigns)

    assert GuardianSocket.current_resource(socket) == claims["sub"]
  end

  test "does not have a current resource when there is no one logged in", %{socket: socket} do
    assert GuardianSocket.current_resource(socket) == nil
  end

  test "is authenticated if there is a token present", %{socket: socket} do
    assert GuardianSocket.authenticated?(socket) == false

    key = Guardian.Keys.jwt_key
    assigns = %{key => "THE JWT"}
    socket = Map.put(socket, :assigns, assigns)

    assert GuardianSocket.authenticated?(socket) == true
  end

  test "is authenticated if there is a token present in the secret location", %{socket: socket} do
    assert GuardianSocket.authenticated?(socket, :secret) == false

    key = Guardian.Keys.jwt_key(:secret)
    assigns = %{key => "THE JWT"}
    socket = Map.put(socket, :assigns, assigns)

    assert GuardianSocket.authenticated?(socket, :secret) == true
  end

  test "sign in with a nil JWT", %{socket: socket} do
    assert GuardianSocket.sign_in(socket, nil) == {:error, :no_token}
  end
end
