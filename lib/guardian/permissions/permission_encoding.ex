defmodule Guardian.Permissions.PermissionEncoding do
  @moduledoc """
  Behavior for the permission encoding
  """

  @callback encode(List.t() | Integer.t(), String.t(), Map.t()) :: term
  @callback decode(List.t() | Integer.t(), String.t(), Map.t()) :: term
end
