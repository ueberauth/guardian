defmodule Guardian.Permissions.PermissionEncoding do
  @callback encode_permissions!(Guardian.Permissions.Bitwise.input_permissions() | nil) ::
              Guardian.Permissions.Bitwise.t()
  @callback decode_permissions(term) :: String.t()

  @callback validate_permissions!(map) :: String.t()
end
