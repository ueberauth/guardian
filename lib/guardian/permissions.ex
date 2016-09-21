defmodule Guardian.Permissions do
  @moduledoc """
  Functions for dealing with permissions sets.

  Guardian provides facilities for working with
  many permission sets in parallel.
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

  Guardian.Permissions encodes the permissions for each as integer bitstrings
  so you have 31 permissions per group.
  (remember javascript is only a 32 bit system)
  Guardian tokens will remain small, event with a full 31 permissions in a set.
  You should use less sets and more permissions,
  rather than more sets with fewer permissions per set.
  Permissions that are unknown are ignored.
  This is to support backwards compatibility with previously issued tokens.

  ### Example working with permissions manually

      # Accessing default permissions
      Guardian.Permissions.to_value([:read_profile, :write_profile]) # 3
      Guardian.Permissions.to_list(3) # [:read_profile, :write_profile]

      # Accessing 'admin' permissions (see config above)
      Guardian.Permissions.to_value(
        [:financials_read, :financials_write], :admin
      ) # 12

      # [:financials_read, :financials_write]
      Guardian.Permissions.to_list(12, :admin)

      # Checking permissions
      # true
      Guardian.Permissions.all?(3, [:users_read, :users_write], :admin)

      # false
      Guardian.Permissions.all?(1, [:users_read, :users_write], :admin)

      # true
      Guardian.Permissions.any?(12, [:users_read, :financial_read], :admin)

      # true
      Guardian.Permissions.any?(11, [:read_profile, :read_item])

      # false
      Guardian.Permissions.any?(11, [:delete_item, :write_item])

  ### Reading permissions from claims

  Permissions are encoded into claims under the :pem key
  and are a map of "type": <value as integer>

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

      Guardian.Claims.permissions(
        existing_claims,
        admin: [:users_read],
        default: [:read_item, :write_item]
      )

  Assign all permissions (and all future ones)

      max = Guardian.Permissions.max
      Guardian.Claims.permissions(existing_claims, admin: max, default: max)

  ### Signing in with permissions

  This will encode the permissions as a map with integer values

      Guardian.Plug.sign_in(
        user,
        :access
        perms: %{ admin: [:users_read],
        default: [:read_item, :write_item] }
      )

  ### Encoding credentials with permissions

  This will encode the permissions as a map with integer values

      Guardian.encode_and_sign(
        user,
        :access,
        perms: %{
          admin: [:users_read],
          default: [:read_item, :write_item]
        }
      )

  """
  use Bitwise


  def max, do: -1

  @doc """
  Fetches the list of known permissions for the given type
  """
  @spec available(atom) :: List
  def available, do: available(:default)
  def available(type) when is_binary(type) do
    try do
      available(String.to_existing_atom(type))
    rescue
      _e in ArgumentError -> []
    end
  end

  def available(type) when is_atom(type), do: Map.get(all_available(), type, [])

  def all_available, do: Enum.into(Guardian.config(:permissions, %{}), %{})

  def all?(value, expected, key \\ :default) do
    expected_value = to_value(expected, key)
    if expected_value == 0 do
      false
    else
      (to_value(value, key) &&& expected_value) == expected_value
    end
  end

  def any?(value, expected, key \\ :default) do
    expected_value = to_value(expected, key)
    (to_value(value, key) &&& expected_value) > 0
  end

  @doc """
  Fetches the permissions from the claims.
  Permissions live in the :pem key and are a map of
    "<type>": <value of permissions as integer>
  """
  @spec from_claims(map) :: list
  def from_claims(claims), do: from_claims(claims, :default)

  def from_claims(claims, type) do
    c = Map.get(claims, "pem", %{})
    Map.get(c, type, Map.get(c, to_string(type), 0))
  end

  def to_value(val), do: to_value(val, :default)

  @doc """
  Fetches the value as a bitstring (integer)
  of the list of permissions in the `type` list
  """
  @spec to_value(integer | list, atom) :: integer
  def to_value(num, _) when is_integer(num), do: num

  @doc false
  def to_value(list, type) when is_list(list) do
    to_value(list, 0, available(type))
  end

  def to_value(_, acc, []), do: acc

  @doc false
  def to_value([], acc, _), do: acc

  # match two lists against each other
  def to_value([h|t], acc, perms) do
    idx = Enum.find_index(perms, &(&1 == h or to_string(&1) == h))
    if idx do
      to_value(t, Bitwise.bor(acc, trunc(:math.pow(2,idx))), perms)
    else
      to_value(t, acc, perms)
    end
  end

  def to_list(thing), do: to_list(thing, :default)
  def to_list(thing, type), do: to_list(thing, [], available(type))
  def to_list(_,_,[]), do: []

  # When given a list of things
  def to_list(list, _acc, perms) when is_list(list) do
    string_perms = Enum.map(perms, &to_string/1)
    list
    |> Enum.map(fn
      x when is_atom(x) ->
        if Enum.member?(perms, x), do: x
      x when is_binary(x) ->
        if Enum.member?(string_perms, x), do: String.to_existing_atom(x)
      _ -> nil
    end)
    |> Enum.filter(&(&1 != nil))
  end

  # When given a number
  def to_list(num, _acc, perms) when is_integer(num) do
    for i <- (0..(length(perms) - 1)),
             Bitwise.band(num, trunc(:math.pow(2,i))) != 0
    do
     Enum.at(perms, i)
    end
  end
end
