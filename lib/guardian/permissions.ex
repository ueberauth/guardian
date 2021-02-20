defmodule Guardian.Permissions do
  @moduledoc """
  An optional plugin to Guardian to provide permissions for your tokens.

  These can be used for any token types since they only work on the `claims`.

  Permissions are set on a per implementation module basis.
  Each implementation module can have their own sets.
  Permissions are similar in concept to OAuth2 scopes. They're encoded into a token
  and the permissions granted last as long as the token does.
  This makes it unsuitable for highly dynamic permission schemes.
  They're best left to an application to implement.

  For example. (at the time of writing) some of the Facebook permissions are:

  * public_profile
  * user_about_me
  * user_actions.books
  * user_actions.fitness
  * user_actions.music

  To create permissions for your application similar to these:

  ```elixir
  defmodule MyApp.Auth.Token do

    use Guardian, otp_app: :my_app,
                           permissions: %{
                           default: [:public_profile, :user_about_me]
                           user_actions: %{
                             books: 0b1,
                             fitness: 0b100,
                             music: 0b1000,
                           }
                         }

    use Guardian.Permissions, :encoding: Guardian.Permissions.BitwiseEncoding
    # Per default permissons will be encoded Bitwise, but other encoders also exist
    #  * Guardian.Permissions.TextEncoding
    #  * Guardian.Permissions.AtomEncoding
    # It is even posible to supply your own encoding module

    # snip

    def build_claims(claims, _resource, opts) do
      claims =
        claims
        |> encode_permissions_into_claims!(Keyword.get(opts, :permissions))
      {:ok, claims}
    end
  end
  ```

  This will take the permission set in the `opts` at `:permissions` and
  put it into the `"pems"` key of the claims as a map of `%{set_name => integer}`.

  The permissions can be defined as a list (positional value based on index)
  or a map where the value for each permission is manually provided.

  They can be provided either as options to `use Guardian` or in the config for
  your implementation module.

  Once you have a token, you can interact with it.

  ```elixir
  # Get the encoded permissions from the claims
  found_perms = MyApp.Auth.Token.decode_permissions_from_claims(claims)

  # Check if all permissions are present
  has_all_these_things? =
    claims
    |> MyApp.Auth.Token.decode_permissions_from_claims
    |> MyApp.Auth.Token.all_permissions?(%{default: [:user_about_me, :public_profile]})

  # Checks if any permissions are present
  show_any_media_things? =
    claims
    |> MyApp.Auth.Token.decode_permissions_from_claims
    |> MyApp.Auth.Token.any_permissions?(%{user_actions: [:books, :fitness, :music]})
  ```

  ### Using with Plug

  To use a plug for ensuring permissions you can use the `Guardian.Permissions` module as part of a
  Guardian pipeline.

  ```elixir
  # After a pipeline has setup the implementation module and error handler

  # Ensure that both the `public_profile` and `user_actions.books` permissions
  # are present in the token
  plug Guardian.Permissions, ensure: %{default: [:public_profile], user_actions: [:books]}

  # Allow the request to continue when the token contains any of the permission sets specified
  plug Guardian.Permissions, one_of: [
    %{default: [:public_profile], user_actions: [:books]},
    %{default: [:public_profile], user_actions: [:music]},
  ]

  # Look for permissions for a token in a different location
  plug Guardian.Permissions, key: :impersonate, ensure: %{default: [:public_profile]}
  ```

  If the token satisfies either the permissions listed in `ensure` or one of
  the sets in the `one_of` key the request will continue. If not, then
  `auth_error` callback will be called on the error handler with
  `auth_error(conn, {:unauthorized, reason}, options)`.
  """

  @type label :: atom
  @type permission_label :: String.t() | atom
  @type permission :: pos_integer
  @type permission_set :: [permission_label, ...] | %{optional(label) => permission}
  @type t :: %{optional(label) => permission_set}

  @type input_label :: permission_label
  @type input_set :: permission_set | permission
  @type input_permissions :: %{optional(input_label) => input_set}

  @type plug_option ::
          {:ensure, permission_set}
          | {:one_of, [permission_set, ...]}
          | {:key, atom}
          | {:module, module}
          | {:error_handler, module}

  defmodule PermissionNotFoundError do
    defexception [:message]
  end

  defmacro __using__(opts \\ []) do
    # Credo is incorrectly identifying an unless block with negated condition 2017-06-10
    # credo:disable-for-next-line /\.Refactor\./
    quote do
      alias Guardian.Permissions.PermissionNotFoundError
      import unquote(Keyword.get(opts, :encoding, Guardian.Permissions.BitwiseEncoding))

      defdelegate max(), to: Guardian.Permissions

      raw_perms = @config_with_key.(:permissions)

      unless raw_perms do
        raise "Permissions are not defined for #{to_string(__MODULE__)}"
      end

      @normalized_perms Guardian.Permissions.normalize_permissions(raw_perms)
      @available_permissions Guardian.Permissions.available_from_normalized(@normalized_perms)

      @doc """
      Lists all permissions in a normalized way using
      `%{permission_set_name => [permission_name, ...]}`.
      """

      @spec available_permissions() :: Guardian.Permissions.t()
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
      @spec decode_permissions(Guardian.Permissions.input_permissions() | nil) :: Guardian.Permissions.t()
      def decode_permissions(nil), do: %{}

      def decode_permissions(map) when is_map(map) do
        for {k, v} <- map, Map.get(@normalized_perms, to_string(k)) != nil, into: %{} do
          key = k |> to_string() |> String.to_atom()
          {key, do_decode_permissions(v, k)}
        end
      end

      @doc """
      Decodes permissions directly from a claims map. This does the same as `decode_permissions` but
      will fetch the permissions map from the `"pem"` key where `Guardian.Permissions places them
      when it encodes them into claims.
      """
      @spec decode_permissions_from_claims(Guardian.Token.claims()) :: Guardian.Permissions.t()
      def decode_permissions_from_claims(%{"pem" => perms}), do: decode_permissions(perms)
      def decode_permissions_from_claims(_), do: %{}

      @doc """
      Encodes the permissions provided into the claims in the `"pem"` key.
      Permissions are encoded into an integer inside the token corresponding
      with the value provided in the configuration.
      """
      @spec encode_permissions_into_claims!(
              Guardian.Token.claims(),
              Guardian.Permissions.input_permissions() | nil
            ) :: Guardian.Token.claims()
      def encode_permissions_into_claims!(claims, nil), do: claims

      def encode_permissions_into_claims!(claims, perms) do
        encoded_perms = encode_permissions!(perms)
        Map.put(claims, "pem", encoded_perms)
      end

      @doc """
      Checks to see if any of the permissions provided are present
      in the permissions (previously extracted from claims).

          iex> claims |> MyTokens.decode_permissions() |> any_permissions?(%{user_actions: [:books, :music]})
          true
      """
      @spec any_permissions?(
              Guardian.Permissions.input_permissions(),
              Guardian.Permissions.input_permissions()
            ) :: boolean
      def any_permissions?(has_perms, test_perms) when is_map(test_perms) do
        has_perms = decode_permissions(has_perms)
        test_perms = decode_permissions(test_perms)

        Enum.any?(test_perms, fn {k, needs} ->
          has_perms |> Map.get(k) |> do_any_permissions?(MapSet.new(needs))
        end)
      end

      defp do_any_permissions?(nil, _), do: false

      defp do_any_permissions?(list, needs) do
        matches = MapSet.intersection(needs, MapSet.new(list))
        MapSet.size(matches) > 0
      end

      @doc """
      Checks to see if all of the permissions provided are present
      in the permissions (previously extracted from claims).

          iex> claims |> MyTokens.decode_permissions() |> all_permissions?(%{user_actions: [:books, :music]})
          true

      """
      @spec all_permissions?(
              Guardian.Permissions.input_permissions(),
              Guardian.Permissions.input_permissions()
            ) :: boolean
      def all_permissions?(has_perms, test_perms) when is_map(test_perms) do
        has_perms_bits = decode_permissions(has_perms)
        test_perms_bits = decode_permissions(test_perms)

        Enum.all?(test_perms_bits, fn {k, needs} ->
          has = Map.get(has_perms_bits, k, [])
          MapSet.subset?(MapSet.new(needs), MapSet.new(has))
        end)
      end

      @doc """
      Encodes the permissions provided into numeric form.

          iex> MyTokens.encode_permissions!(%{user_actions: [:books, :music]})
          %{user_actions: 9}

      """
      @spec encode_permissions!(Guardian.Permissions.input_permissions() | nil) :: Guardian.Permissions.t()
      def encode_permissions!(nil), do: %{}

      def encode_permissions!(map) when is_map(map) do
        for {k, v} <- map, into: %{} do
          key = String.to_atom(to_string(k))
          {key, do_encode_permissions!(v, k)}
        end
      end

      @doc """
      Validates that all permissions provided exist in the configuration.

          iex> MyTokens.validate_permissions!(%{default: [:user_about_me]})

          iex> MyTokens.validate_permissions!(%{not: [:a, :thing]})
          raise Guardian.Permissions.PermissionNotFoundError

      """
      def validate_permissions!(map) when is_map(map) do
        Enum.all?(&do_validate_permissions!/1)
      end

      defp do_decode_permissions(other), do: do_decode_permissions(other, "default")

      defp do_decode_permissions(value, type) when is_atom(type),
        do: do_decode_permissions(value, to_string(type))

      defp do_decode_permissions(value, type) when is_integer(value) do
        decode(value, type, @normalized_perms)
      end

      defp do_decode_permissions(value, type) do
        do_validate_permissions!({type, value})
        decode(value, type, @normalized_perms)
      end

      defp do_encode_permissions!(value, type) when is_atom(type),
        do: do_encode_permissions!(value, to_string(type))

      defp do_encode_permissions!(value, type) when is_integer(value) do
        encode(value, type, @normalized_perms)
      end

      defp do_encode_permissions!(value, type) do
        do_validate_permissions!({type, value})
        encode(value, type, @normalized_perms)
      end

      defp do_validate_permissions!({type, value}) when is_atom(type),
        do: do_validate_permissions!({to_string(type), value})

      defp do_validate_permissions!({type, map}) when is_map(map) do
        list = map |> Map.keys() |> Enum.map(&to_string/1)
        do_validate_permissions!({type, list})
      end

      defp do_validate_permissions!({type, list}) when is_list(list) do
        perm_set = Map.get(@normalized_perms, type)

        if perm_set do
          provided_set = list |> Enum.map(&to_string/1) |> MapSet.new()
          known_set = perm_set |> Map.keys() |> MapSet.new()

          diff = MapSet.difference(provided_set, known_set)

          if MapSet.size(diff) > 0 do
            message = "#{to_string(__MODULE__)} Type: #{type} Missing Permissions: #{Enum.join(diff, ", ")}"
            raise PermissionNotFoundError, message: message
          end

          :ok
        else
          raise PermissionNotFoundError, message: "#{to_string(__MODULE__)} - Type: #{type}"
        end
      end

      defp do_validate_permissions!({type, value}) do
        do_validate_permissions!({type, [value]})
      end
    end
  end

  defdelegate init(opts), to: Guardian.Permissions.Plug
  defdelegate call(conn, opts), to: Guardian.Permissions.Plug

  @doc """
  Provides an encoded version of all permissions, and all possible future permissions
  for a permission set.
  """
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
end
