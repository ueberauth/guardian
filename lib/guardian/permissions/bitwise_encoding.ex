defmodule Guardian.Permissions.BitwiseEncoding do
  def max, do: -1

  @doc false
  def normalize_permissions(perms) do
    perms = Enum.into(perms, %{})

    for {k, v} <- perms, into: %{} do
      case v do
        # A list of permission names.
        # Positional values
        list
        when is_list(list) ->
          perms =
            for {perm, idx} <- Enum.with_index(list), into: %{} do
              {to_string(perm), trunc(:math.pow(2, idx))}
            end

          {to_string(k), perms}

        # A map of permissions. The permissions should be name => bit value
        map
        when is_map(map) ->
          perms = for {perm, val} <- map, into: %{}, do: {to_string(perm), val}
          {to_string(k), perms}
      end
    end
  end

  @doc false
  def available_from_normalized(perms) do
    for {k, v} <- perms, into: %{} do
      list = v |> Map.keys() |> Enum.map(&String.to_atom/1)
      {String.to_atom(k), list}
    end
  end

  defmacro __using__(_opts \\ []) do
    alias Guardian.Permissions.Bitwise.PermissionNotFoundError
    use Bitwise
    # Credo is incorrectly identifying an unless block with negated condition 2017-06-10
    # credo:disable-for-next-line /\.Refactor\./
    quote do
      raw_perms = @config_with_key.(:permissions)
      @behaviour Guardian.Permissions.PermissionEncoding

      unless raw_perms do
        raise "Permissions are not defined for #{to_string(__MODULE__)}"
      end

      @normalized_perms Guardian.Permissions.BitwiseEncoding.normalize_permissions(raw_perms)
      @available_permissions Guardian.Permissions.BitwiseEncoding.available_from_normalized(
                               @normalized_perms
                             )

      @spec available_permissions() :: Guardian.Permissions.Bitwise.t()
      def available_permissions, do: @available_permissions

      @doc """
      Decodes permissions from the permissions found in claims (encoded to integers) or
      from a list of permissions.

         iex> MyTokens.decode_permissions(%{default: [:public_profile]})
         %{default: [:public_profile]}

         iex> MyTokens.decode_permissions{%{"default" => 1, "user_actions" => 1}}
         %{default: [:public_profile], user_actions: [:books]}

      When using integers (after encoding to claims), unknown bit positions are ignored.

          iex> MyTokens.decode_permissions(%{"default" => -1})
          %{default: [:public_profile, :user_about_me]}
      """
      @spec decode_permissions(Guardian.Permissions.Bitwise.input_permissions() | nil) ::
              Guardian.Permissions.Bitwise.t()
      def decode_permissions(nil), do: %{}

      def decode_permissions(map) when is_map(map) do
        for {k, v} <- map, Map.get(@normalized_perms, to_string(k)) != nil, into: %{} do
          key = k |> to_string() |> String.to_atom()
          {key, do_decode_permissions(v, k)}
        end
      end

      @doc """
      Encodes the permissions provided into numeric form

      iex> MyTokens.encode_permissions!(%{user_actions: [:books, :music]})
      %{user_actions: 9}
      """
      @spec encode_permissions!(Guardian.Permissions.Bitwise.input_permissions() | nil) ::
              Guardian.Permissions.Bitwise.t()
      def encode_permissions!(nil), do: %{}

      def encode_permissions!(map) when is_map(map) do
        for {k, v} <- map, into: %{} do
          key = String.to_atom(to_string(k))
          {key, do_encode_permissions!(v, k)}
        end
      end

      defp do_decode_permissions(other), do: do_decode_permissions(other, "default")

      defp do_decode_permissions(value, type) when is_atom(type),
        do: do_decode_permissions(value, to_string(type))

      defp do_decode_permissions(value, type) when is_list(value) do
        do_validate_permissions!({type, value})
        value |> Enum.map(&to_string/1) |> Enum.map(&String.to_atom/1)
      end

      defp do_decode_permissions(value, type) when is_integer(value) do
        perms = Map.get(@normalized_perms, type)

        for {k, v} <- perms, band(value, v) == v, into: [] do
          k |> to_string() |> String.to_atom()
        end
      end

      defp do_encode_permissions!(value, type) when is_atom(type),
        do: do_encode_permissions!(value, to_string(type))

      defp do_encode_permissions!(value, _type) when is_integer(value), do: value

      defp do_encode_permissions!(value, type) when is_list(value) do
        do_validate_permissions!({type, value})
        perms = Map.get(@normalized_perms, type)
        Enum.reduce(value, 0, &encode_value(&1, perms, &2))
      end

      defp encode_value(value, perm_set, acc),
        do: perm_set |> Map.get(to_string(value)) |> bor(acc)
    end
  end
end
