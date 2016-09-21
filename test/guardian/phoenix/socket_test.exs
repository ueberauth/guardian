defmodule Guardian.Phoenix.SocketTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Guardian.Phoenix.Socket, as: GuardianSocket

  defmodule TestSocket do
    @moduledoc false

    defstruct assigns: %{}
  end

  setup do
    claims = %{
      "aud" => "User:1",
      "typ" => "access",
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

    {_, jwt} = jose_jwk |> JOSE.JWT.sign(jose_jws, claims) |> JOSE.JWS.compact

    {:ok, %{
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
    assigns = %{} |> Map.put(key, %{"the" => "claims"})
    socket = Map.put(socket, :assigns, assigns)

    assert GuardianSocket.current_claims(socket) == %{"the" => "claims"}
  end

  test "current_claims from socket in secret location", %{socket: socket} do
    key = Guardian.Keys.claims_key(:secret)
    assigns = %{} |> Map.put(key, %{"the" => "claim"})
    socket = Map.put(socket, :assigns, assigns)

    assert GuardianSocket.current_claims(socket, :secret) == %{"the" => "claim"}
  end

  test "current_token from socket", %{socket: socket} do
    key = Guardian.Keys.jwt_key
    assigns = %{} |> Map.put(key, "THE JWT")
    socket = Map.put(socket, :assigns, assigns)

    assert GuardianSocket.current_token(socket) == "THE JWT"
  end

  test "current_token from socket secret location", %{socket: socket} do
    key = Guardian.Keys.jwt_key(:secret)
    assigns = %{} |> Map.put(key, "THE JWT")
    socket = Map.put(socket, :assigns, assigns)

    assert GuardianSocket.current_token(socket, :secret) == "THE JWT"
  end

  test "fetch serialized sub for current_resource", %{socket: s, claims: c} do
    key = Guardian.Keys.claims_key
    assigns = %{} |> Map.put(key, c)
    socket = Map.put(s, :assigns, assigns)

    assert GuardianSocket.current_resource(socket) == c["sub"]
  end

  test "does not have a current resource with no one logged in", %{socket: s} do
    assert GuardianSocket.current_resource(s) == nil
  end

  test "is authenticated if there is a token present", %{socket: socket} do
    refute GuardianSocket.authenticated?(socket)

    key = Guardian.Keys.jwt_key
    assigns = %{} |> Map.put(key, "THE JWT")
    socket = Map.put(socket, :assigns, assigns)

    assert GuardianSocket.authenticated?(socket)
  end

  test "authenticated if token present in the secret location", %{socket: s} do
    refute GuardianSocket.authenticated?(s, :secret)

    key = Guardian.Keys.jwt_key(:secret)
    assigns = %{} |> Map.put(key, "THE JWT")
    socket = Map.put(s, :assigns, assigns)

    assert GuardianSocket.authenticated?(socket, :secret)
  end

  test "sign in with a nil JWT", %{socket: socket} do
    assert GuardianSocket.sign_in(socket, nil) == {:error, :no_token}
  end
end
