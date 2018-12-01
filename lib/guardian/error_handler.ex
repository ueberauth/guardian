defmodule Guardian.ErrorHandler do

  @callback auth_error(conn :: Plug.Conn.t(), {atom, atom}, Guardian.options()) :: Plug.Conn.t()
end
