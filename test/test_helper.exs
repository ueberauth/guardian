defmodule Guardian.TestGuardianSerializer do
  @moduledoc false

  @behaviour Guardian.Serializer
  def for_token(%{error: :unknown}), do: {:error, "Unknown resource type"}

  def for_token(aud), do: {:ok, aud}
  def from_token(aud), do: {:ok, aud}
end

defmodule Guardian.TestHelper do
  @moduledoc false

  @default_opts [
    store: :cookie,
    key: "foobar",
    encryption_salt: "encrypted cookie salt",
    signing_salt: "signing salt"
  ]

  @secret String.duplicate("abcdef0123456789", 8)
  @signing_opts Plug.Session.init(Keyword.put(@default_opts, :encrypt, false))

  def conn_with_fetched_session(the_conn) do
    the_conn.secret_key_base
    |> put_in(@secret)
    |> Plug.Session.call(@signing_opts)
    |> Plug.Conn.fetch_session
  end

  @doc """
  Helper for running a plug.

  Calls the plug module's `init/1` function with
  no arguments and passes the results to `call/2`
  as the second argument.
  """
  def run_plug(conn, plug_module) do
    opts = apply(plug_module, :init, [])
    apply(plug_module, :call, [conn, opts])
  end

  @doc """
  Helper for running a plug.

  Calls the plug module's `init/1` function with
  the value of `plug_opts` and passes the results to
  `call/2` as the second argument.
  """
  def run_plug(conn, plug_module, plug_opts) do
    opts = apply(plug_module, :init, [plug_opts])
    apply(plug_module, :call, [conn, opts])
  end

  @doc """
  Helper for simulating a tuple to be used by `apply/3` to get a `secret_key`

  It simply returns whatever secret it is given.
  """

  def secret_key_function(secret), do: secret

  def build_jwt(claims) do
    config = Application.get_env(:guardian, Guardian)
    algo = hd(Keyword.get(config, :allowed_algos))
    secret = Keyword.get(config, :secret_key)

    jose_jws = %{"alg" => algo}
    jose_jwk = %{"kty" => "oct", "k" => :base64url.encode(secret)}
    {_, jwt} = jose_jwk
                 |> JOSE.JWT.sign(jose_jws, claims)
                 |> JOSE.JWS.compact
    jwt
  end
end

ExUnit.start()
