defmodule Guardian.Plug.EnsureResource do
  @moduledoc """
  This plug ensures that the current_resource has been set, usually in
  Guardian.Plug.LoadResource.

  If one is not found, the `no_resource/2` function is invoked with the
  `Plug.Conn.t` object and its params.

  ## Example

      # Will call the no_resource/2 function on your handler
      plug Guardian.Plug.EnsureResource, handler: SomeModule

      # look in the :secret location.
      plug Guardian.Plug.EnsureResource, handler: SomeModule, key: :secret

  If the handler option is not passed, `Guardian.Plug.ErrorHandler` will provide
  the default behavior.
  """
  require Logger
  import Plug.Conn

  @doc false
  def init(opts) do
    opts = Enum.into(opts, %{})
    handler = build_handler_tuple(opts)

    %{
      handler: handler,
      key: Map.get(opts, :key, :default)
    }
  end

  @doc false
  def call(conn, opts) do
    key = Map.get(opts, :key, :default)

    case Guardian.Plug.current_resource(conn, key) do
      nil -> handle_error(conn, opts)
      _ -> conn
    end
  end

  defp handle_error(%Plug.Conn{params: params} = conn, opts) do
    conn = conn |> assign(:guardian_failure, :no_resource) |> halt
    params = Map.merge(params, %{reason: :no_resource})

    {mod, meth} = Map.get(opts, :handler)

    apply(mod, meth, [conn, params])
  end

  defp build_handler_tuple(%{handler: mod}) do
    {mod, :no_resource}
  end
  defp build_handler_tuple(%{on_failure: {mod, fun}}) do
    _ = Logger.warn(":on_failure is deprecated. Use the :handler option instead")
    {mod, fun}
  end
  defp build_handler_tuple(_) do
    {Guardian.Plug.ErrorHandler, :no_resource}
  end
end
