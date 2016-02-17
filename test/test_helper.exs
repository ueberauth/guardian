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
end

ExUnit.start()
