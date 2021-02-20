defmodule Guardian.Permissions.PermissionEncoding do
  @moduledoc """
  Behavior for the permission encoding.
  """

  @callback encode(list() | integer(), String.t(), map()) :: term
  @callback decode(list() | integer(), String.t(), map()) :: term
end
