defmodule Guardian.Plug.KeysTest do
  @moduledoc false

  # async: false so the atom-table measurement below is not polluted by atoms
  # interned in other modules running concurrently.
  use ExUnit.Case, async: false

  import Plug.Test

  alias Guardian.Plug.Keys

  describe "unbounded atom creation (GHSA-xqch-c77q-rgh5 / CVE-2026-54894)" do
    test "lookups never intern atoms for previously unseen binary keys" do
      for i <- 1..2_000 do
        key = "attacker_tenant_#{i}_#{:erlang.unique_integer([:positive])}"

        assert Keys.token_key(key) == nil
        assert Keys.claims_key(key) == nil
        assert Keys.resource_key(key) == nil
        assert Keys.base_key(key) == nil

        # The namespace atom must not exist as a side effect of the lookup.
        assert_raise ArgumentError, fn -> String.to_existing_atom("guardian_#{key}_token") end
      end
    end

    test "current_token with a request-controlled key returns nil without interning atoms" do
      for i <- 1..2_000 do
        tenant = "attacker_tenant_#{i}_#{:erlang.unique_integer([:positive])}"

        assert Guardian.Plug.current_token(conn(:get, "/"), key: tenant) == nil
        assert_raise ArgumentError, fn -> String.to_existing_atom("guardian_#{tenant}_token") end
      end
    end

    test "key_from_other never interns atoms from arbitrary binaries" do
      for i <- 1..2_000 do
        segment = "attacker_#{i}_#{:erlang.unique_integer([:positive])}"

        assert Keys.key_from_other("guardian_#{segment}_token") == segment
        assert_raise ArgumentError, fn -> String.to_existing_atom(segment) end
      end
    end

    test "attacker traffic does not grow the atom table proportionally" do
      # Warm up so one-time atom interning (Plug.Test conn building, etc.) is
      # already paid for before we measure.
      for warm <- ["warmup_a", "warmup_b"] do
        Guardian.Plug.current_token(conn(:get, "/"), key: warm)
      end

      before = :erlang.system_info(:atom_count)
      requests = 5_000

      for i <- 1..requests do
        tenant = "attacker_tenant_#{i}_#{:erlang.unique_integer([:positive])}"
        Guardian.Plug.current_token(conn(:get, "/"), key: tenant)
      end

      delta = :erlang.system_info(:atom_count) - before

      assert delta == 0,
             "expected no new atoms from #{requests} attacker requests, but #{delta} were created"
    end
  end

  describe "key derivation behaviour" do
    test "known keys resolve to the documented atoms" do
      assert Keys.token_key(:default) == :guardian_default_token
      assert Keys.claims_key(:default) == :guardian_default_claims
      assert Keys.resource_key(:default) == :guardian_default_resource
      assert Keys.base_key(:default) == :guardian_default
    end

    test "an already-namespaced binary is not double-prefixed" do
      _ = Keys.token_key!("guardian_default")
      assert Keys.base_key("guardian_default") == :guardian_default
    end

    test "bang variants create the storage atom and lookups then find it" do
      key = "tenant_#{:erlang.unique_integer([:positive])}"

      created = Keys.token_key!(key)
      assert is_atom(created)
      assert Atom.to_string(created) == "guardian_#{key}_token"
      assert Keys.token_key(key) == created
    end

    test "string builders match the atom string form for session/cookie names" do
      assert Keys.token_key_string(:default) == "guardian_default_token"
      assert Keys.token_key_string("tenant") == "guardian_tenant_token"
      assert Keys.token_key_string("guardian_tenant") == "guardian_tenant_token"
      assert Keys.claims_key_string(:default) == "guardian_default_claims"
      assert Keys.resource_key_string(:default) == "guardian_default_resource"
    end

    test "non-binary keys derive namespaces through String.Chars" do
      assert Keys.token_key_string(123) == "guardian_123_token"

      created = Keys.token_key!(123)
      assert created == :guardian_123_token
      assert Keys.token_key(123) == created
    end

    test "key_from_other resolves existing base atoms and falls back to strings" do
      assert Keys.key_from_other(:guardian_default_token) == :default

      tenant = "tenant_#{:erlang.unique_integer([:positive])}"
      stored = Keys.token_key!(tenant)

      assert Keys.key_from_other(stored) == tenant
      assert_raise ArgumentError, fn -> String.to_existing_atom(tenant) end
    end
  end

  describe "round-trip through Guardian.Plug with a dynamic key" do
    test "put then read a token under the same namespace" do
      key = "tenant_#{:erlang.unique_integer([:positive])}"

      conn =
        conn(:get, "/")
        |> Guardian.Plug.put_current_token("the-token", key: key)

      assert Guardian.Plug.current_token(conn, key: key) == "the-token"
      assert Guardian.Plug.authenticated?(conn, key: key)
      refute Guardian.Plug.authenticated?(conn, key: "some-other-tenant")
    end
  end
end
