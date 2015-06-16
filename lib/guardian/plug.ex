defmodule Guardian.Plug do
  import Guardian.Utils

  def sign_in(conn, object, type), do: sign_in(conn, object, type, %{})

  def sign_in(conn, object, type, claims) do
    the_key = Dict.get(claims, :key, :default)
    claims = Dict.delete(claims, :key)

    case Guardian.mint(object, type, claims) do
      { :ok, jwt } ->
        conn
        |> Plug.Conn.put_session(base_key(the_key), jwt)
        |> set_current_resource(object, the_key)

      { :error, reason } -> Plug.Conn.put_session(conn, base_key(the_key), { :error, reason }) # TODO: handle this failure
    end
  end

  def logout(conn, the_key \\ :all) do
    conn
    |> clear_resource_assign(the_key)
    |> logout_via_key(the_key)
  end

  def claims(conn, the_key \\ :default) do
    case conn.assigns[claims_key(the_key)] do
      { :ok, claims } -> { :ok, claims }
      { :error, reason } -> { :error, reason }
      _ -> { :error, :no_session }
    end
  end

  def set_claims(conn, claims, the_key \\ :default) do
    Plug.Conn.assign(conn, claims_key(the_key), claims)
  end

  def current_resource(conn, the_key \\ :default) do
    conn.assigns[resource_key(the_key)]
  end

  def set_current_resource(conn, resource, the_key \\ :default) do
    Plug.Conn.assign(conn, resource_key(the_key), resource)
  end

  def current_token(conn, the_key \\ :default) do
    conn.assigns[jwt_key(the_key)]
  end

  def set_current_token(conn, jwt, the_key \\ :default) do
    Plug.Conn.assign(conn, jwt_key(the_key), jwt)
  end

  def claims_key(key), do: String.to_atom("#{base_key(key)}_claims")
  def resource_key(key), do: String.to_atom("#{base_key(key)}_resource")
  def jwt_key(key), do: String.to_atom("#{base_key(key)}_jwt")

  def base_key(the_key = "guardian_" <> _), do: String.to_atom(the_key)
  def base_key(the_key), do: String.to_atom("guardian_#{the_key}")

  defp logout_via_key(conn, :all), do: Plug.Conn.clear_session(conn)
  defp logout_via_key(conn, the_key), do: Plug.Conn.delete_session(conn, claims_key(the_key))

  defp clear_resource_assign(conn, :all) do
    Dict.keys(conn.assigns)
    |> Enum.filter(&(String.starts_with?(to_string(&1), "guardian_")))
    |> Enum.reduce(conn, fn(key, c) -> Plug.Conn.assign(c, key, nil) end)
  end

  defp clear_resource_assign(conn, key), do: Plug.Conn.assign(conn, resource_key(key), nil)
end
