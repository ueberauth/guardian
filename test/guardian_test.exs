defmodule GuardianTest do
  @moduledoc false

  defmodule Impl do
    @moduledoc false
    use Guardian, otp_app: :guardian,
                  token_module: Guardian.Support.TokenModule

    import Guardian.Support.Utils, only: [
      print_function_call: 1,
    ]

    def subject_for_token(%{id: id} = r, claims) do
      print_function_call({__MODULE__, :subject_for_token, [r, claims]})
      {:ok, id}
    end

    def subject_for_token(%{"id" => id} = r, claims) do
      print_function_call({__MODULE__, :subject_for_token, [r, claims]})
      {:ok, id}
    end

    def resource_from_claims(%{"sub" => id} = claims) do
      print_function_call({__MODULE__, :subject_for_token, [claims]})
      {:ok, %{id: id}}
    end

    def build_claims(claims, resource, options) do
      print_function_call({
        __MODULE__,
        :build_claims,
        [claims, resource, options]
      })

      if Keyword.get(options, :fail_build_claims) do
        {:error, Keyword.get(options, :fail_build_claims)}
      else
        {:ok, claims}
      end
    end

    def after_encode_and_sign(resource, claims, token, options) do
      print_function_call({
        __MODULE__,
        :after_encode_and_sign,
        [resource, claims, token, options]
      })

      if Keyword.get(options, :fail_after_encode_and_sign) do
        {:error, Keyword.get(options, :fail_after_encode_and_sign)}
      else
        {:ok, token}
      end
    end

    def after_sign_in(conn, location) do
      print_function_call({
        __MODULE__,
        :after_sign_in,
        [:conn, location]
      })
      conn
    end

    def before_sign_out(conn, location) do
      print_function_call({
        __MODULE__,
        :before_sign_out,
        [:conn, location]
      })
      conn
    end

    def verify_claims(claims, options) do
      print_function_call({
        __MODULE__,
        :verify_claims,
        [claims, options]
      })

      if Keyword.get(options, :fail_mod_verify_claims) do
        {:error, Keyword.get(options, :fail_mod_verify_claims)}
      else
        {:ok, claims}
      end
    end

    def on_verify(claims, token, options) do
      print_function_call({
        __MODULE__,
        :on_verify,
        [claims, token, options]
      })

      if Keyword.get(options, :fail_on_verify) do
        {:error, Keyword.get(options, :fail_on_verify)}
      else
        {:ok, claims}
      end
    end

    def on_revoke(claims, token, options) do
      print_function_call({
        __MODULE__,
        :on_revoke,
        [claims, token, options]
      })

      if Keyword.get(options, :fail_on_revoke) do
        {:error, Keyword.get(options, :fail_on_revoke)}
      else
        {:ok, token}
      end
    end
  end

  defmodule EncodeAndSign do
    @moduledoc "Testing Guardian.encode_and_sign"
    use ExUnit.Case, async: true
    import ExUnit.CaptureIO
    import Guardian.Support.Utils, only: [filter_function_calls: 1]

    @impl __MODULE__
            |> Module.split()
            |> List.pop_at(-1)
            |> elem(1)
            |> List.insert_at(-1, :Impl)
            |> Module.concat()

    @resource %{id: "bobby"}

    test "the impl has access to it's config" do
      assert @impl.config(:token_module) == Guardian.Support.TokenModule
    end

    test "encode_and_sign with only a resource" do
      io = capture_io(fn ->
        {:ok, _token, full_claims} =
          Guardian.encode_and_sign(
            @impl,
            @resource,
            %{},
            []
          )

        assert full_claims ==
          %{"sub" => "bobby"}
      end)

      function_calls = filter_function_calls(io)

      expected = [
        "GuardianTest.Impl.subject_for_token(%{id: \"bobby\"}, %{})",
        "Guardian.Support.TokenModule.build_claims(GuardianTest.Impl, %{id: \"bobby\"}, \"bobby\", %{}, [])",
        "GuardianTest.Impl.build_claims(%{\"sub\" => \"bobby\"}, %{id: \"bobby\"}, [])",
        "Guardian.Support.TokenModule.create_token(GuardianTest.Impl, %{\"sub\" => \"bobby\"}, [])",
        "GuardianTest.Impl.after_encode_and_sign(%{id: \"bobby\"}, %{\"sub\" => \"bobby\"}, \"{\\\"claims\\\":{\\\"sub\\\":\\\"bobby\\\"}}\", [])",
      ]

      assert function_calls == expected
    end

    test "with custom claims" do
      claims = %{some: "claim"}
      io = capture_io(fn ->
        {:ok, _token, full_claims} =
          Guardian.encode_and_sign(
            @impl,
            @resource,
            claims,
            []
          )

        assert full_claims ==
          %{"sub" => "bobby", "some" => "claim"}
      end)

      function_calls = filter_function_calls(io)

      expected = [
        "GuardianTest.Impl.subject_for_token(%{id: \"bobby\"}, %{\"some\" => \"claim\"})",
        "Guardian.Support.TokenModule.build_claims(GuardianTest.Impl, %{id: \"bobby\"}, \"bobby\", %{\"some\" => \"claim\"}, [])",
        "GuardianTest.Impl.build_claims(%{\"some\" => \"claim\", \"sub\" => \"bobby\"}, %{id: \"bobby\"}, [])",
        "Guardian.Support.TokenModule.create_token(GuardianTest.Impl, %{\"some\" => \"claim\", \"sub\" => \"bobby\"}, [])",
        "GuardianTest.Impl.after_encode_and_sign(%{id: \"bobby\"}, %{\"some\" => \"claim\", \"sub\" => \"bobby\"}, \"{\\\"claims\\\":{\\\"sub\\\":\\\"bobby\\\",\\\"some\\\":\\\"claim\\\"}}\", [])"
      ]

      assert function_calls == expected
    end

    test "encode_and_sign with options" do
      claims = %{some: "claim"}
      options = [some: "option"]
      io = capture_io(fn ->
        {:ok, _token, full_claims} =
          Guardian.encode_and_sign(
            @impl,
            @resource,
            claims,
            options
          )

        assert full_claims ==
          %{"sub" => "bobby", "some" => "claim"}
      end)

      function_calls = filter_function_calls(io)

      expected = [
        "GuardianTest.Impl.subject_for_token(%{id: \"bobby\"}, %{\"some\" => \"claim\"})",
        "Guardian.Support.TokenModule.build_claims(GuardianTest.Impl, %{id: \"bobby\"}, \"bobby\", %{\"some\" => \"claim\"}, [some: \"option\"])",
        "GuardianTest.Impl.build_claims(%{\"some\" => \"claim\", \"sub\" => \"bobby\"}, %{id: \"bobby\"}, [some: \"option\"])",
        "Guardian.Support.TokenModule.create_token(GuardianTest.Impl, %{\"some\" => \"claim\", \"sub\" => \"bobby\"}, [some: \"option\"])",
        "GuardianTest.Impl.after_encode_and_sign(%{id: \"bobby\"}, %{\"some\" => \"claim\", \"sub\" => \"bobby\"}, \"{\\\"claims\\\":{\\\"sub\\\":\\\"bobby\\\",\\\"some\\\":\\\"claim\\\"}}\", [some: \"option\"])"
      ]

      assert function_calls == expected
    end

    test "encode_and_sign when build_claims fails" do
      capture_io(fn ->
        {:error, :bad_things} =
          Guardian.encode_and_sign(
            @impl,
            @resource,
            %{},
            [fail_build_claims: :bad_things]
          )
      end)
    end

    test "encode_and_sign when after_encode_and_sign fails" do
      capture_io(fn ->
        {:error, :bad_things} =
          Guardian.encode_and_sign(
            @impl,
            @resource,
            %{},
            [fail_after_encode_and_sign: :bad_things]
          )
      end)
    end

    test "encode_and_sign when create_token fails in the token module" do
      capture_io(fn ->
        {:error, :bad_things} =
          Guardian.encode_and_sign(
            @impl,
            @resource,
            %{},
            [fail_create_token: :bad_things]
          )
      end)
    end
  end

  defmodule DecodeAndVerify do
    @moduledoc "Testing Guardian.decode_and_verify"
    use ExUnit.Case, async: true

    import ExUnit.CaptureIO
    import Guardian.Support.Utils, only: [filter_function_calls: 1]

    @impl __MODULE__
          |> Module.split()
          |> List.pop_at(-1)
          |> elem(1)
          |> List.insert_at(-1, :Impl)
          |> Module.concat()

    setup do
      claims = %{
        "sub" => "freddy",
        "some" => "other_claim"
      }
      {:ok, token: Poison.encode!(%{claims: claims}), claims: claims}
    end

    test "simple decode", %{token: token, claims: claims} do
      io = capture_io(fn ->
        {:ok, ^claims} =
          Guardian.decode_and_verify(@impl, token, %{}, [])
      end)

      function_calls = filter_function_calls(io)

      expected = [
        "Guardian.Support.TokenModule.decode_token(GuardianTest.Impl, \"{\\\"claims\\\":{\\\"sub\\\":\\\"freddy\\\",\\\"some\\\":\\\"other_claim\\\"}}\", [])",
        "Guardian.Support.TokenModule.verify_claims(GuardianTest.Impl, %{\"some\" => \"other_claim\", \"sub\" => \"freddy\"}, [])",
        "GuardianTest.Impl.verify_claims(%{\"some\" => \"other_claim\", \"sub\" => \"freddy\"}, [])",
        "GuardianTest.Impl.on_verify(%{\"some\" => \"other_claim\", \"sub\" => \"freddy\"}, \"{\\\"claims\\\":{\\\"sub\\\":\\\"freddy\\\",\\\"some\\\":\\\"other_claim\\\"}}\", [])"
      ]

      assert function_calls == expected
    end

    test "verifying specific claims", %{claims: claims, token: token} do
      capture_io(fn ->
        {:ok, ^claims} =
          Guardian.decode_and_verify(
            @impl,
            token,
            %{some: "other_claim"}
          )
      end)
    end

    test "a failing claim check", %{token: token} do
      capture_io(fn ->
        {:error, "not_a"} =
          Guardian.decode_and_verify(
            @impl,
            token,
            %{not_a: "thing"}
          )
      end)
    end

    test "failure on decoding", %{token: token} do
      capture_io(fn ->
        {:error, :decode_failure} =
          Guardian.decode_and_verify(
            @impl,
            token,
            %{},
            [fail_decode_token: :decode_failure]
          )
      end)
    end

    test "fails verifying within the token module", %{token: token} do
      capture_io(fn ->
        {:error, :verify_failure} =
          Guardian.decode_and_verify(
            @impl,
            token,
            %{},
            [fail_verify_claims: :verify_failure]
          )
      end)
    end

    test "fails verifying within the module", %{token: token} do
      capture_io(fn ->
        {:error, :verify_failure} =
          Guardian.decode_and_verify(
            @impl,
            token,
            %{},
            [fail_mod_verify_claims: :verify_failure]
          )
      end)
    end

    test "fails on verify", %{token: token} do
      capture_io(fn ->
        {:error, :on_verify_failure} =
          Guardian.decode_and_verify(
            @impl,
            token,
            %{},
            [fail_on_verify: :on_verify_failure]
          )
      end)
    end
  end
end
