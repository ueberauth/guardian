defmodule Guardian.Permissions.Plug do
  @moduledoc false
  alias Guardian.Plug.Pipeline

  @doc false
  @spec init([Guardian.Permissions.plug_option()]) :: [Guardian.Permissions.plug_option()]
  def init(opts) do
    ensure = Keyword.has_key?(opts, :ensure)
    one_of = Keyword.has_key?(opts, :one_of)

    if ensure and one_of do
      raise "`:ensure` and `:one_of` cannot both be specified for plug #{to_string(__MODULE__)}."
    end

    if ensure do
      ensure_map =
        opts
        |> Keyword.get(:ensure, [])
        |> Enum.into(%{})

      Keyword.put(opts, :ensure, ensure_map)
    else
      opts
    end
  end

  @doc false
  @spec call(conn :: Plug.Conn.t(), opts :: Keyword.t()) :: Plug.Conn.t()
  def call(conn, opts) do
    context = %{
      claims: Guardian.Plug.current_claims(conn, opts),
      ensure: Keyword.get(opts, :ensure),
      handler: Pipeline.fetch_error_handler!(conn, opts),
      impl: Pipeline.fetch_module!(conn, opts),
      one_of: Keyword.get(opts, :one_of)
    }

    check_permissions(conn, context, opts)
  end

  defp check_permissions(conn, %{ensure: nil, one_of: nil}, _), do: conn

  defp check_permissions(conn, %{claims: nil, handler: handler}, opts) do
    handle_response(false, conn, :missing_claims, handler, opts)
  end

  # Ensure permissions
  defp check_permissions(conn, %{claims: claims, ensure: ensure, handler: handler, impl: impl, one_of: nil}, opts) do
    has_perms = apply(impl, :decode_permissions_from_claims, [claims])

    impl
    |> apply(:all_permissions?, [has_perms, ensure])
    |> handle_response(conn, :insufficient_permission, handler, opts)
  end

  # One_of permissions
  defp check_permissions(conn, %{claims: claims, ensure: nil, handler: handler, impl: impl, one_of: one_of}, opts) do
    has_perms = apply(impl, :decode_permissions_from_claims, [claims])

    one_of
    |> Enum.any?(&apply(impl, :all_permissions?, [has_perms, &1]))
    |> handle_response(conn, :insufficient_permission, handler, opts)
  end

  defp handle_response(true, conn, _reason, _handler, _opts),
    do: conn

  defp handle_response(false, conn, reason, handler, opts),
    do: apply(handler, :auth_error, [conn, {:unauthorized, reason}, opts])
end
