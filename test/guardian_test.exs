defmodule GuardianTest do
  @moduledoc false

  import Guardian.Support.Utils, only: [gather_function_calls: 0]

  use ExUnit.Case, async: true

  setup do
    {:ok, %{impl: GuardianTest.Impl}}
  end

  defmodule Impl do
    @moduledoc false
    use Guardian,
      otp_app: :guardian,
      token_module: Guardian.Support.TokenModule

    import Guardian.Support.Utils,
      only: [
        send_function_call: 1
      ]

    def subject_for_token(%{id: id} = r, claims) do
      send_function_call({__MODULE__, :subject_for_token, [r, claims]})
      {:ok, id}
    end

    def subject_for_token(%{"id" => id} = r, claims) do
      send_function_call({__MODULE__, :subject_for_token, [r, claims]})
      {:ok, id}
    end

    def resource_from_claims(%{"sub" => id} = claims) do
      send_function_call({__MODULE__, :subject_for_token, [claims]})
      {:ok, %{id: id}}
    end

    def build_claims(claims, resource, options) do
      send_function_call({__MODULE__, :build_claims, [claims, resource, options]})

      if Keyword.get(options, :fail_build_claims) do
        {:error, Keyword.get(options, :fail_build_claims)}
      else
        {:ok, claims}
      end
    end

    def after_encode_and_sign(resource, claims, token, options) do
      send_function_call({__MODULE__, :after_encode_and_sign, [resource, claims, token, options]})

      if Keyword.get(options, :fail_after_encode_and_sign) do
        {:error, Keyword.get(options, :fail_after_encode_and_sign)}
      else
        {:ok, token}
      end
    end

    def after_sign_in(conn, location) do
      send_function_call({__MODULE__, :after_sign_in, [:conn, location]})
      conn
    end

    def before_sign_out(conn, location) do
      send_function_call({__MODULE__, :before_sign_out, [:conn, location]})
      conn
    end

    def verify_claims(claims, options) do
      send_function_call({__MODULE__, :verify_claims, [claims, options]})

      if Keyword.get(options, :fail_mod_verify_claims) do
        {:error, Keyword.get(options, :fail_mod_verify_claims)}
      else
        {:ok, claims}
      end
    end

    def on_verify(claims, token, options) do
      send_function_call({__MODULE__, :on_verify, [claims, token, options]})

      if Keyword.get(options, :fail_on_verify) do
        {:error, Keyword.get(options, :fail_on_verify)}
      else
        {:ok, claims}
      end
    end

    def on_revoke(claims, token, options) do
      send_function_call({__MODULE__, :on_revoke, [claims, token, options]})

      if Keyword.get(options, :fail_on_revoke) do
        {:error, Keyword.get(options, :fail_on_revoke)}
      else
        {:ok, claims}
      end
    end

    def on_refresh(old_stuff, new_stuff, options) do
      send_function_call({__MODULE__, :on_refresh, [old_stuff, new_stuff, options]})

      if Keyword.get(options, :fail_on_refresh) do
        {:error, Keyword.get(options, :fail_on_refresh)}
      else
        {:ok, old_stuff, new_stuff}
      end
    end

    def on_exchange(old_stuff, new_stuff, options) do
      send_function_call({__MODULE__, :on_exchange, [old_stuff, new_stuff, options]})

      if Keyword.get(options, :fail_on_exchange) do
        {:error, Keyword.get(options, :fail_on_exchange)}
      else
        {:ok, old_stuff, new_stuff}
      end
    end
  end

  describe "encode_and_sign" do
    @resource %{id: "bobby"}
    test "the impl has access to it's config", ctx do
      assert ctx.impl.config(:token_module) == Guardian.Support.TokenModule
    end

    test "encode_and_sign with only a resource", ctx do
      assert {:ok, token, full_claims} = Guardian.encode_and_sign(ctx.impl, @resource, %{}, [])

      assert full_claims == %{"sub" => "bobby", "typ" => "access"}

      expected = [
        {ctx.impl, :subject_for_token, [%{id: "bobby"}, %{}]},
        {Guardian.Support.TokenModule, :build_claims, [ctx.impl, @resource, "bobby", %{}, []]},
        {ctx.impl, :build_claims, [full_claims, @resource, []]},
        {Guardian.Support.TokenModule, :create_token, [ctx.impl, full_claims, []]},
        {ctx.impl, :after_encode_and_sign, [@resource, full_claims, token, []]}
      ]

      assert gather_function_calls() == expected
    end

    test "with custom claims", ctx do
      claims = %{"some" => "claim"}
      assert {:ok, token, full_claims} = Guardian.encode_and_sign(ctx.impl, @resource, claims, [])

      assert full_claims == %{"sub" => "bobby", "some" => "claim", "typ" => "access"}

      expected = [
        {ctx.impl, :subject_for_token, [@resource, claims]},
        {Guardian.Support.TokenModule, :build_claims, [ctx.impl, @resource, "bobby", claims, []]},
        {ctx.impl, :build_claims, [full_claims, @resource, []]},
        {Guardian.Support.TokenModule, :create_token, [ctx.impl, full_claims, []]},
        {ctx.impl, :after_encode_and_sign, [@resource, full_claims, token, []]}
      ]

      assert gather_function_calls() == expected
    end

    test "encode_and_sign with options", ctx do
      claims = %{"some" => "claim"}
      options = [some: "option"]

      assert {:ok, token, full_claims} =
               Guardian.encode_and_sign(ctx.impl, @resource, claims, options)

      assert full_claims == %{"sub" => "bobby", "some" => "claim", "typ" => "access"}

      expected = [
        {ctx.impl, :subject_for_token, [@resource, claims]},
        {Guardian.Support.TokenModule, :build_claims,
         [ctx.impl, @resource, "bobby", claims, options]},
        {ctx.impl, :build_claims, [full_claims, @resource, options]},
        {Guardian.Support.TokenModule, :create_token, [ctx.impl, full_claims, options]},
        {ctx.impl, :after_encode_and_sign, [@resource, full_claims, token, options]}
      ]

      assert gather_function_calls() == expected
    end

    test "encode_and_sign when build_claims fails", ctx do
      assert {:error, :bad_things} =
               Guardian.encode_and_sign(ctx.impl, @resource, %{}, fail_build_claims: :bad_things)
    end

    test "encode_and_sign when after_encode_and_sign fails", ctx do
      assert {:error, :bad_things} =
               Guardian.encode_and_sign(
                 ctx.impl,
                 @resource,
                 %{},
                 fail_after_encode_and_sign: :bad_things
               )
    end

    test "encode_and_sign when create_token fails in the token module", ctx do
      assert {:error, :bad_things} =
               Guardian.encode_and_sign(ctx.impl, @resource, %{}, fail_create_token: :bad_things)
    end
  end

  describe "decode_and_verify" do
    setup %{impl: impl} do
      claims = %{"sub" => "freddy", "some" => "other_claim"}
      {:ok, token, claims} = Guardian.encode_and_sign(impl, @resource, claims)
      gather_function_calls()
      {:ok, token: token, claims: claims}
    end

    test "simple decode", ctx do
      claims = ctx.claims
      assert {:ok, ^claims} = Guardian.decode_and_verify(ctx.impl, ctx.token, %{}, [])

      expected = [
        {Guardian.Support.TokenModule, :decode_token, [ctx.impl, ctx.token, []]},
        {Guardian.Support.TokenModule, :verify_claims, [ctx.impl, claims, []]},
        {ctx.impl, :verify_claims, [claims, []]},
        {GuardianTest.Impl, :on_verify, [claims, ctx.token, []]}
      ]

      assert gather_function_calls() == expected
    end

    test "verifying specific claims", ctx do
      claims = ctx.claims

      assert {:ok, ^claims} =
               Guardian.decode_and_verify(ctx.impl, ctx.token, %{some: "other_claim"})
    end

    test "a failing claim check", ctx do
      assert {:error, "not_a"} =
               Guardian.decode_and_verify(ctx.impl, ctx.token, %{not_a: "thing"})
    end

    test "failure on decoding", ctx do
      assert {:error, :decode_failure} =
               Guardian.decode_and_verify(
                 ctx.impl,
                 ctx.token,
                 %{},
                 fail_decode_token: :decode_failure
               )
    end

    test "fails verifying within the token module", ctx do
      assert {:error, :verify_failure} =
               Guardian.decode_and_verify(
                 ctx.impl,
                 ctx.token,
                 %{},
                 fail_verify_claims: :verify_failure
               )
    end

    test "fails verifying within the module", ctx do
      assert {:error, :verify_failure} =
               Guardian.decode_and_verify(
                 ctx.impl,
                 ctx.token,
                 %{},
                 fail_mod_verify_claims: :verify_failure
               )
    end

    test "fails on verify", ctx do
      assert {:error, :on_verify_failure} =
               Guardian.decode_and_verify(
                 ctx.impl,
                 ctx.token,
                 %{},
                 fail_on_verify: :on_verify_failure
               )
    end
  end

  describe "resource_from_token" do
    setup %{impl: impl} do
      claims = %{"sub" => "freddy", "some" => "other_claim"}
      {:ok, token, claims} = Guardian.encode_and_sign(impl, @resource, claims)
      gather_function_calls()
      {:ok, token: token, claims: claims}
    end

    test "it finds the resource", ctx do
      resource = @resource
      claims = ctx.claims

      assert {:ok, ^resource, ^claims} =
               Guardian.resource_from_token(ctx.impl, ctx.token, %{}, [])
    end

    test "it returns an error when token can't be decoded", ctx do
      invalid_token = -1

      assert {:error, :invalid_token} =
               Guardian.resource_from_token(ctx.impl, invalid_token, %{}, [])
    end
  end

  describe "revoke" do
    setup %{impl: impl} do
      claims = %{"sub" => "freddy", "some" => "other_claim"}
      {:ok, token, claims} = Guardian.encode_and_sign(impl, @resource, claims)
      gather_function_calls()
      {:ok, token: token, claims: claims}
    end

    test "it calls all the right things", ctx do
      claims = ctx.claims
      assert {:ok, ^claims} = Guardian.revoke(ctx.impl, ctx.token, [])

      expected = [
        {Guardian.Support.TokenModule, :revoke, [ctx.impl, claims, ctx.token, []]},
        {GuardianTest.Impl, :on_revoke, [claims, ctx.token, []]}
      ]

      assert gather_function_calls() == expected
    end

    test "it fails before going to the impl if the token module fails", ctx do
      assert {:error, :fails} = Guardian.revoke(ctx.impl, ctx.token, fail_revoke: :fails)

      expected = [
        {Guardian.Support.TokenModule, :revoke,
         [ctx.impl, ctx.claims, ctx.token, [fail_revoke: :fails]]}
      ]

      assert gather_function_calls() == expected
    end
  end

  describe "refresh" do
    setup %{impl: impl} do
      claims = %{"sub" => "freddy", "some" => "other_claim"}
      {:ok, token, claims} = Guardian.encode_and_sign(impl, @resource, claims)
      gather_function_calls()
      {:ok, token: token, claims: claims}
    end

    test "it calls all the right things", ctx do
      claims = ctx.claims
      token = ctx.token
      assert {:ok, {^token, ^claims}, {new_t, new_c}} = Guardian.refresh(ctx.impl, ctx.token, [])

      expected = [
        {Guardian.Support.TokenModule, :decode_token, [ctx.impl, ctx.token, []]},
        {Guardian.Support.TokenModule, :verify_claims, [ctx.impl, ctx.claims, []]},
        {ctx.impl, :verify_claims, [ctx.claims, []]},
        {ctx.impl, :on_verify, [ctx.claims, ctx.token, []]},
        {Guardian.Support.TokenModule, :refresh, [ctx.impl, ctx.token, []]},
        {Guardian.Support.TokenModule, :decode_token, [ctx.impl, ctx.token, []]},
        {ctx.impl, :on_refresh, [{ctx.token, ctx.claims}, {new_t, new_c}, []]}
      ]

      assert gather_function_calls() == expected
    end

    test "it fails before going to the impl if the token module fails", ctx do
      assert {:error, :fails} = Guardian.refresh(ctx.impl, ctx.token, fail_refresh: :fails)

      expected = [
        {Guardian.Support.TokenModule, :decode_token,
         [ctx.impl, ctx.token, [fail_refresh: :fails]]},
        {Guardian.Support.TokenModule, :verify_claims,
         [ctx.impl, ctx.claims, [fail_refresh: :fails]]},
        {ctx.impl, :verify_claims, [ctx.claims, [fail_refresh: :fails]]},
        {ctx.impl, :on_verify, [ctx.claims, ctx.token, [fail_refresh: :fails]]},
        {Guardian.Support.TokenModule, :refresh, [ctx.impl, ctx.token, [fail_refresh: :fails]]}
      ]

      assert gather_function_calls() == expected
    end
  end

  describe "exchange" do
    setup %{impl: impl} do
      claims = %{"sub" => "freddy", "some" => "other_claim"}
      {:ok, token, claims} = Guardian.encode_and_sign(impl, @resource, claims)
      gather_function_calls()
      {:ok, token: token, claims: claims}
    end

    test "it calls all the right things", ctx do
      claims = ctx.claims
      token = ctx.token

      assert {:ok, {^token, ^claims}, {new_t, new_c}} =
               Guardian.exchange(ctx.impl, token, claims["typ"], "refresh", [])

      expected = [
        {Guardian.Support.TokenModule, :decode_token, [ctx.impl, ctx.token, []]},
        {Guardian.Support.TokenModule, :verify_claims, [ctx.impl, ctx.claims, []]},
        {ctx.impl, :verify_claims, [ctx.claims, []]},
        {ctx.impl, :on_verify, [ctx.claims, ctx.token, []]},
        {Guardian.Support.TokenModule, :exchange, [ctx.impl, ctx.token, "access", "refresh", []]},
        {Guardian.Support.TokenModule, :decode_token, [ctx.impl, ctx.token, []]},
        {GuardianTest.Impl, :on_exchange, [{ctx.token, ctx.claims}, {new_t, new_c}, []]}
      ]

      assert gather_function_calls() == expected
    end

    test "it fails before going to the impl if the token module fails", ctx do
      claims = ctx.claims
      token = ctx.token

      assert {:error, :fails} =
               Guardian.exchange(
                 ctx.impl,
                 ctx.token,
                 claims["typ"],
                 "refresh",
                 fail_exchange: :fails
               )

      expected = [
        {Guardian.Support.TokenModule, :decode_token, [ctx.impl, token, [fail_exchange: :fails]]},
        {Guardian.Support.TokenModule, :verify_claims,
         [ctx.impl, claims, [fail_exchange: :fails]]},
        {ctx.impl, :verify_claims, [claims, [fail_exchange: :fails]]},
        {ctx.impl, :on_verify, [claims, token, [fail_exchange: :fails]]},
        {Guardian.Support.TokenModule, :exchange,
         [ctx.impl, token, "access", "refresh", [fail_exchange: :fails]]}
      ]

      assert gather_function_calls() == expected
    end
  end
end
