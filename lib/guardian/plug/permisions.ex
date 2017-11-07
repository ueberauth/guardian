if Code.ensure_loaded?(Plug) do
  defmodule Guardian.Plug.Permisions do
    import Plug.Conn
    
    alias Guardian.Plug, as: GPlug
    alias Guardian.Plug.Pipeline

    def init(opts) do
      ensure = Keyword.get(opts, :ensure)
      one_of = Keyword.get(opts, :one_of)
      if ensure && one_of do
        raise ":permissions and a :one_of cannot both be specified for plug #{to_string __MODULE__} "
      end

      opts =
        if Keyword.keyword?(ensure) do
          ensure = ensure |> Enum.into(%{})
          Keyword.put(opts, :ensure, ensure)
        else
          opts
        end

      opts
    end

    def call(conn, opts) do
      context = %{
        claims: GPlug.current_claims(conn, opts),
        ensure: Keyword.get(opts, :ensure),
        handler: Pipeline.fetch_error_handler!(conn, opts),
        impl: Pipeline.fetch_module!(conn, opts),
        one_of: Keyword.get(opts, :one_of)
      }
      do_call(conn, context, opts)
    end

    defp do_call(conn, %{ensure: nil, one_of: nil}, _), do: conn
    defp do_call(conn, %{claims: nil} = ctx, opts) do
      ctx.handler
      |> apply(:auth_error, [conn, {:unauthorized, :unauthorized}, opts])
      |> halt()
    end

    # single set of permissions to check
    defp do_call(conn, %{one_of: nil} = ctx, opts) do
      has_perms = apply(ctx.impl, :decode_permissions_from_claims, [ctx.claims])
      is_ok? = apply(ctx.impl, :all_permissions?, [has_perms, ctx.ensure])

      if is_ok? do
        conn
      else
        ctx.handler
        |> apply(:auth_error, [conn, {:unauthorized, :unauthorized}, opts])
        |> halt()
      end
    end

    # one_of sets of permissions to check
    defp do_call(conn, %{ensure: nil} = ctx, opts) do
      has_perms = apply(ctx.impl, :decode_permissions_from_claims, [ctx.claims])
      is_ok? =
        Enum.any? ctx.one_of, fn test_perms ->
          apply(ctx.impl, :all_permissions?, [has_perms, test_perms])
        end

      if is_ok? do
        conn
      else
        ctx.handler
        |> apply(:auth_error, [conn, {:unauthorized, :unauthorized}, opts])
        |> halt()
      end
    end
  end
end