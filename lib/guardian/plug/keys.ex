defmodule Guardian.Plug.Keys do
  @moduledoc """
  Calculates keys for use with plug.

  The keys relate to where in the session/connection
  the data that Guardian deals in will be stored.

  `token`, `claims`, `resource` are all keyed.
  `token`, `claims`, `resource` are all stored on the conn.
  `token` is stored in the session if a session is found.

  ## Atom safety

  A Guardian "key" names a namespace on the connection. Because these keys are
  ultimately used as atoms (`Plug.Conn` private storage is atom-keyed), turning
  an arbitrary binary into an atom would let attacker-influenced input (a tenant
  id, a header, ...) create unbounded, never-collected atoms and exhaust the
  BEAM atom table (GHSA-xqch-c77q-rgh5 / CVE-2026-54894).

  To stay safe the lookup helpers (`token_key/1`, `claims_key/1`,
  `resource_key/1`, `base_key/1`) never create atoms from binaries: they resolve
  through `String.to_existing_atom/1` and return `nil` when the atom does not
  exist, which reads back as "nothing stored under this namespace". New namespace
  atoms are only ever created through the write-only bang helpers
  (`token_key!/1`, `claims_key!/1`, `resource_key!/1`), whose key comes from
  developer configuration rather than request data. Session and cookie names use
  the string helpers (`token_key_string/1`, ...) and need no atom at all.

  `key_from_other/1` recovers the base key from a namespace that is already
  stored on the connection. String-keyed setups intern only the suffixed atoms
  (e.g. `:guardian_acme_token`, never `:acme`), so when the bare atom does not
  exist the key is returned as a string rather than dropped - `sign_out(:all)`
  must still find those namespaces. All key helpers accept any term that
  implements `String.Chars` (atoms, binaries, integers, ...).
  """

  @prefix "guardian_"

  @doc false
  @spec claims_key() :: atom
  @spec claims_key(String.t() | atom) :: atom
  def claims_key(key \\ :default), do: existing_key(key, "_claims")

  @doc false
  @spec resource_key() :: atom
  @spec resource_key(String.t() | atom) :: atom
  def resource_key(key \\ :default), do: existing_key(key, "_resource")

  @doc false
  @spec token_key() :: atom
  @spec token_key(String.t() | atom) :: atom
  def token_key(key \\ :default), do: existing_key(key, "_token")

  @doc false
  @spec base_key(String.t() | atom) :: atom
  def base_key(key), do: existing_key(key, "")

  @doc false
  @spec claims_key!(String.t() | atom) :: atom
  def claims_key!(key \\ :default), do: created_key(key, "_claims")

  @doc false
  @spec resource_key!(String.t() | atom) :: atom
  def resource_key!(key \\ :default), do: created_key(key, "_resource")

  @doc false
  @spec token_key!(String.t() | atom) :: atom
  def token_key!(key \\ :default), do: created_key(key, "_token")

  @doc false
  @spec claims_key_string(String.t() | atom) :: String.t()
  def claims_key_string(key \\ :default), do: base_string(key) <> "_claims"

  @doc false
  @spec resource_key_string(String.t() | atom) :: String.t()
  def resource_key_string(key \\ :default), do: base_string(key) <> "_resource"

  @doc false
  @spec token_key_string(String.t() | atom) :: String.t()
  def token_key_string(key \\ :default), do: base_string(key) <> "_token"

  @doc false
  def key_from_other(other_key) when is_binary(other_key) do
    ~r/^guardian_(?<key>.+)_(token|resource|claims)$/
    |> Regex.named_captures(other_key)
    |> extract_key()
  end

  def key_from_other(atom) do
    atom
    |> to_string()
    |> key_from_other()
  end

  defp existing_key(key, suffix) do
    string = base_string(key) <> suffix

    # Scope the rescue to the conversion alone: a binary that names no existing
    # atom means "nothing stored under this namespace", so it reads back as `nil`,
    # never a crash and never a newly interned atom.
    try do
      String.to_existing_atom(string)
    rescue
      ArgumentError -> nil
    end
  end

  defp created_key(key, suffix) do
    key
    |> base_string()
    |> Kernel.<>(suffix)
    |> String.to_atom()
  end

  defp base_string(key) when is_atom(key), do: @prefix <> Atom.to_string(key)
  defp base_string(@prefix <> _ = key), do: key
  defp base_string(key) when is_binary(key), do: @prefix <> key
  defp base_string(key), do: @prefix <> to_string(key)

  # A string-keyed namespace interns only the suffixed atoms, so the bare atom
  # may not exist; return the string form then so the namespace is still found
  # (notably by `sign_out(:all)`), without interning a new atom.
  defp extract_key(%{"key" => key}) do
    String.to_existing_atom(key)
  rescue
    ArgumentError -> key
  end

  defp extract_key(_), do: nil
end
