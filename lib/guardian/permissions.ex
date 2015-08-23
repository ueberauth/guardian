defmodule Guardian.Permissions do
  @moduledoc """
  Functions for dealing with permissions sets.

  Guardian provides facilities for working with many permission sets in parallel.
  Guardian must be configured with it's permissions at start time.

      config :guardian, Guardian,
             permissions: %{
               default: [
                 :read_profile,
                 :write_profile,
                 :create_item,
                 :read_item,
                 :write_item,
                 :delete_item
               ],
              admin: [
                :users_read,
                :users_write,
                :financials_read,
                :financials_write,
              ]
             }

  Guardian.Permissions encodes the permissions for each as bitstrings (integers) so you have 31 permissions per group. (remember javascript is only a 32 bit system)
  Guardian tokens will remain small, event with a full 31 permissions in a set. You should use less sets and more permissions, rather than more sets with fewer permissions per set.
  Permissions that are unknown are ignored. This is to support backwards compatibility with previously issued tokens.

  ### Example working with permissions manually

      # Accessing default permissions
      Guardian.Permissions.to_value([:read_profile, :write_profile]) # 3
      Guardian.Permissions.to_list(3) # [:read_profile, :write_profile]

      # Accessing 'admin' permissions (see config above)
      Guardian.Permissions.to_value([:financials_read, :financials_write], :admin) # 12
      Guardian.Permissions.to_list(12, :admin) # [:financials_read, :financials_write]

      # Checking permissions
      Guardian.Permissions.all?(3, [:users_read, :users_write], :admin) # true
      Guardian.Permissions.all?(1, [:users_read, :users_write], :admin) # false

      Guardian.Permissions.any?(12, [:users_read, :financial_read], :admin) # true
      Guardian.Permissions.any?(11, [:read_profile, :read_item]) # true
      Guardian.Permissions.any?(11, [:delete_item, :write_item]) # false

  ### Reading permissions from claims

  Permissions are encoded into claims under the :pem key and are a map of "type": <value as integer>
      claims = %{ pem: %{
        "default" => 3,
        "admin" => 1
      } }


      Guardian.Permissions.from_claims(claims) # 3
      Guardian.Permissions.from_claims(claims, :admin) # 1

      # returns [:users_read]
      Guardian.Permissions.from_claims(claims) |> Guardian.Permissions.to_list

  ### Adding permissions to claims

  This will encode the permissions as a map with integer values

      Guardian.Claims.permissions(existing_claims, admin: [:users_read], default: [:read_item, :write_item])

  Assign all permissions (and all future ones)

      max = Guardian.Permissions.max
      Guardian.Claims.permissions(existing_claims, admin: max, default: max)

  ### Signing in with permissions

  This will encode the permissions as a map with integer values

      Guardian.Plug.sign_in(user, :token_type, perms: %{ admin: [:users_read], default: [:read_item, :write_item] })

  ### Minting credentials with permissions

  This will encode the permissions as a map with integer values

      Guardian.mint(user, :token_type, perms: %{ admin: [:users_read], default: [:read_item, :write_item] })

  """
  use Bitwise

  perms = Enum.into(Guardian.config(:permissions, %{}), %{})
  @perms perms
  @max -1

  expanded_perms = Enum.reduce(perms, %{}, fn({key, values}, acc) ->
    perms_as_values = Enum.with_index(values) |> Enum.reduce(%{}, fn({ name, idx}, acc) ->
      Dict.put(acc, name, trunc(:math.pow(2,idx)))
    end)

    Dict.put(acc, key, perms_as_values)
  end)

  Enum.map(expanded_perms, fn({type, values}) ->
    Enum.map(values, fn({name, val}) ->
      def to_value([unquote(name) | tail], unquote(type), acc), do: to_value(tail, unquote(type), Bitwise.bor(acc, unquote(val)) )
      def to_value([unquote(to_string(name)) | tail], unquote(type), acc), do: to_value(tail, unquote(type), Bitwise.bor(acc, unquote(val)) )
      #def to_value(num, acc) when is_integer(num) and Bitwise.band(num, unquote(val)) == unquote(val), do: to_value(Bitwise.bxor(num, unquote(val), unquote(type), Bitwise.bor(acc, unquote(val)))

      def to_list(num, unquote(type), existing_list) when Bitwise.band(unquote(val), num) == unquote(val) do
        to_list(num ^^^ unquote(val), unquote(type), [ unquote(name) | existing_list])
      end
    end)

    def from_claims(claims, unquote(type)) do
      c = Dict.get(claims, :pem, Dict.get(claims, "pem", %{}))
      Dict.get(c, unquote(type), Dict.get(c, unquote(to_string(type)), 0))
    end

    def from_claims(claims, unquote(to_string(type))) do
      c = Dict.get(claims, :pem, Dict.get(claims, "pem", %{}))
      Dict.get(c, unquote(type), Dict.get(c, unquote(to_string(type)), 0))
    end
  end)

  def max, do: @max

  @doc """
  Fetches the list of known permissions for the given type
  """
  @spec available(atom) :: List
  def available(type), do: Dict.get(@perms, type, [])

  @doc """
  Fetches the list of known permissions for the default type
  """
  @spec available :: List
  def available, do: Dict.get(@perms, :default, [])


  def all?(value, expected, key \\ :default) do
    expected_value = to_value(expected, key)
    (to_value(value, key) &&& expected_value) == expected_value
  end

  def any?(value, expected, key \\ :default) do
    expected_value = to_value(expected, key)
    (to_value(value, key) &&& expected_value) > 0
  end

  @doc """
  Fetches the permissions from the claims. Permissions live in the :pem key and are a map
  of
    "<type>": <value of permissions as integer>
  """
  @spec from_claims(Map) :: Lsit
  def from_claims(claims), do: from_claims(claims, :default)

  @doc false
  def from_claims(_, _), do: 0

  @doc """
  Fetches the value as a bitstring (integer) of the list of permissions in the default list
  """
  def to_value(list) when is_list(list), do: to_value(list, :default)

  @doc """
  Fetches the value as a bitstring (integer) of the list of permissions in the `type` list
  """
  @spec to_value(Integer) :: Integer
  def to_value(num) when is_integer(num), do: num

  @doc """
  Fetches the value as a bitstring (integer) of the list of permissions in the `type` list
  """
  @spec to_value(Integer, atom) :: Integer
  def to_value(num, _) when is_integer(num), do: num

  @doc false
  def to_value(list, type) when is_list(list), do: to_value(list, type, 0)

  @doc false
  def to_value(atom, type) when is_atom(atom), do: to_value([atom], type, 0)

  @doc false
  def to_value([], _, acc), do: acc

  @doc false
  def to_value([_ | tail], type, val), do: to_value(tail, type, val)

  def to_list(thing), do: to_list(thing, :default)
  def to_list(list, type) when is_list(list), do: list |> to_value(type) |> to_list(type)
  def to_list(num, type) when is_integer(num), do: to_list(num, type, [])
  def to_list(_, _, list), do: list # once we get to here, we've got all we can
end
