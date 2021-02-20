if Code.ensure_loaded?(Plug) do
  defmodule Guardian.Plug.SlidingCookie do
    @moduledoc """
    WARNING! Use of this plug MAY allow a session to be maintained
    indefinitely without primary authentication by issuing new refresh
    tokens off the back of previous (still valid) tokens. Especially if your
    `resource_from_claims` implementation does not check resource validity (in
    a user database or whatever), you SHOULD then at least make such checks
    in the `sliding_cookie/3` implementation to make sure the resource still
    exists, is valid and permitted.

    Indefinite sessions can be prevented by using a `:max_age` configuration
    (which will globally affect the validation of all tokens with an `auth_time`
    claim) or by using the `:max_age` option when validating, and the `:auth_time`
    option when encoding tokens in response to user login. For many simple
    integrations with Phoenix simply using the `:max_age` configuration will
    provide a desirable behaviour. This is subject to using JWT tokens, or
    another token back end which supports the auth_time and max_age features.

    Looks for a valid token in the request cookies, and replaces it, if:

    a. A valid unexpired token is found in the request cookies.
    b. There is a `:sliding_cookie` configuration (or plug option).
    c. The token age (since issue) exceeds that configuration.
    d. The implementation module `sliding_cookie/3` returns `{:ok, new_claims}`.

    Otherwise the plug does nothing.

    The implementation module MUST implement the `sliding_cookie/3` function
    if this plug is used. The return value, if an updated cookie is approved
    of, should be `{:ok, new_claims}`. The `sliding_cookie/3` function should
    take any security action (such as checking a database to check a user has
    not been disabled). Anything else returned will be taken as an indication
    that the cookie should not refreshed.

    The only case whereby the error handler is employed is if the
    `sliding_cookie/3` function is not provided, in which case it is called
    with a type of `:implementation_fault` and reason `:no_sliding_cookie_fn`.

    This, like all other Guardian plugs, requires a Guardian pipeline to be setup.
    It requires an implementation module, an error handler and a key.

    These can be set either:

    1. Upstream on the connection with `plug Guardian.Pipeline`
    2. Upstream on the connection with `Guardian.Pipeline.{put_module, put_error_handler, put_key}`
    3. Inline with an option of `:module`, `:error_handler`, `:key`

    Nothing is done with the token, refreshed or not, no errors are handled as validity and expiry
    can be checked by the VerifyCookie and EnsureAuthenticated plugs respectively.

    Options:

    * `:key` - The location of the token (default `:default`)
    * `:sliding_cookie` - The minimum TTL remaining after which a replacement
      will be issued. Defaults to configured values.
    * `:halt` - Whether to halt the connection in case of error. Defaults to `true`.

    The `:sliding_cookie` config (or plug option) should be the same format as `:ttl`, for example
    `{1, :hour}`, and obviously it should be less than the prevailing `:ttl`.
    """

    import Plug.Conn
    import Guardian.Plug, only: [find_token_from_cookies: 2, maybe_halt: 2]

    alias Guardian.Plug.Pipeline

    import Guardian, only: [ttl_to_seconds: 1, decode_and_verify: 4, timestamp: 0]

    @behaviour Plug

    @impl Plug
    @spec init(opts :: Keyword.t()) :: Keyword.t()
    def init(opts), do: opts

    @impl Plug
    @spec call(conn :: Plug.Conn.t(), opts :: Keyword.t()) :: Plug.Conn.t()
    def call(%{req_cookies: %Plug.Conn.Unfetched{}} = conn, opts) do
      conn
      |> fetch_cookies()
      |> call(opts)
    end

    def call(conn, opts) do
      with {:ok, token} <- find_token_from_cookies(conn, opts),
           module <- Pipeline.fetch_module!(conn, opts),
           {:ok, ttl_softlimit} <- sliding_window(module, opts),
           {:ok, %{"exp" => exp} = claims} <- decode_and_verify(module, token, %{}, opts),
           {:ok, resource} <- module.resource_from_claims(claims),
           true <- timestamp() >= exp - ttl_softlimit,
           {:ok, new_c} <- module.sliding_cookie(claims, resource, opts) do
        conn
        |> Guardian.Plug.remember_me(module, resource, proc_new_claims(new_c, claims), opts)
      else
        {:error, :not_implemented} ->
          conn
          |> Pipeline.fetch_error_handler!(opts)
          |> apply(:auth_error, [conn, {:implementation_fault, :no_sliding_cookie_fn}, opts])
          |> maybe_halt(opts)

        _ ->
          conn
      end
    end

    defp sliding_window(module, opts) do
      case Keyword.get(opts, :sliding_cookie, module.config(:sliding_cookie)) do
        nil ->
          :no_sliding_window

        ttl_descr ->
          {:ok, ttl_to_seconds(ttl_descr)}
      end
    end

    defp proc_new_claims(%{"auth_time" => prev_auth_time} = new_c, %{"auth_time" => prev_auth_time}), do: new_c
    defp proc_new_claims(new_c, %{"auth_time" => prev_auth_time}), do: Map.put(new_c, "auth_time", prev_auth_time)
    defp proc_new_claims(new_c, _old_c), do: new_c
  end
end
