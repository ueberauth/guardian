if Code.ensure_loaded?(Ecto) do
  defmodule Guardian.Token.OneTime do
    @moduledoc """
    A one time token implementation for Guardian.
    This can be used like any other Guardian token, either in a header, or a query string.
    Once decoded once the token is removed and can no longer be used.

    The resource and other data may be encoded into it.

    ### Setup

    ```elixir
    defmodule MyApp.OneTimeToken do
      use Guardian.Token.OneTime, otp_app: :my_app,
                           repo: MyApp.Repo,
                           token_table: "one_time_tokens"

      def subject_for_token(%{id: id}, _), do: {:ok, to_string(id)}
      def resource_from_claims(%{"sub" => id}), do: {:ok, %{id: id}}
    end
    ```

    Configuration can be given via options to use or in the configuration.

    #### Required configuration

    * `repo` - the repository to use for the one time token storage


    #### Optional configuration

    * `token_table` - the table name for where to find tokens. The required fields are `id:string`, `claims:map`, `expiry:utc_datetime`
    * `ttl` - a default ttl for all tokens. If left nil tokens generated will never expire unless explicitly told to

    ### Usage

    ```elixir
    # Create a token
    {:ok, token, _claims} = MyApp.OneTimeToken(my_resource)

    # Create a token with custom data alongside the resource
    {:ok, token, _claims} = MyApp.OneTimeToken(my_resource, %{some: "data"})

    # Create a token with an explicit ttl
    {:ok, token, _claims} = MyApp.OneTimeToken(my_resource, %{some: "data"}, ttl: {2, :hours})
    {:ok, token, _claims} = MyApp.OneTimeToken(my_resource, %{some: "data"}, ttl: {2, :days})
    {:ok, token, _claims} = MyApp.OneTimeToken(my_resource, %{some: "data"}, ttl: {2, :weeks})

    # Create a token with an explicit expiry
    {:ok, token, _claims} = MyApp.OneTimeToken(my_resource, %{some: "data"}, expiry: some_datetime_in_utc)

    # Consume a token
    {:ok, claims} = MyApp.OneTimeToken.decode_and_verify(token)

    # Consume a token and load the resource
    {:ok, resource, claims} = MyApp.OneTimeToken.resource_from_token(token)

    # Revoke a token
    MyApp.OneTimeToken.revoke(token)
    ```
    """
    @behaviour Guardian.Token

    import Ecto.Query, only: [from: 2]

    defmodule Token do
      @moduledoc false
      use Ecto.Schema
      import Ecto.Changeset

      @primary_key false
      schema "abstract_table: tokens" do
        field(:id, :string)
        field(:claims, :map, default: %{})
        field(:expiry, :utc_datetime)
      end

      def changeset(params) do
        %__MODULE__{}
        |> cast(params, [:id, :claims, :expiry])
        |> validate_required([:id])
      end
    end

    defmacro __using__(opts \\ []) do
      opts = [token_module: Guardian.Token.OneTime] ++ opts

      quote do
        use Guardian, unquote(opts)

        def repo, do: Keyword.get(unquote(opts), :repo, config(:repo))
        def token_table, do: config(:token_table, "one_time_tokens")

        defoverridable repo: 0, token_table: 0
      end
    end

    def peek(mod, token) do
      case find_token(mod, token) do
        nil -> nil
        result -> %{claims: result.claims, expiry: result.expiry}
      end
    end

    def token_id, do: UUID.uuid4() |> to_string()

    @doc """
    Build the default claims for the token
    """
    def build_claims(mod, _resource, sub, claims, _opts) do
      claims =
        claims
        |> Guardian.stringify_keys()
        |> Map.put("sub", sub)
        |> Map.put_new("typ", mod.default_token_type())

      {:ok, claims}
    end

    def create_token(mod, claims, opts) do
      data = %{id: token_id(), claims: claims, expiry: find_expiry(mod, claims, opts)}

      result = mod.repo.insert_all({mod.token_table, Token}, [data])

      case result do
        {1, _} ->
          {:ok, data.id}

        _ ->
          {:error, :could_not_create_token}
      end
    end

    @doc """
    Decode the token. Without verification of the claims within it.
    """
    def decode_token(mod, token, _opts) do
      result = find_token(mod, token, DateTime.utc_now())

      if result do
        delete_token(mod, token)
        {:ok, result.claims || %{}}
      else
        {:error, :token_not_found_or_expired}
      end
    end

    @doc """
    Verify the claims of a token
    """
    def verify_claims(_mod, claims, _opts) do
      {:ok, claims}
    end

    @doc """
    Revoke a token (if appropriate)
    """
    def revoke(mod, claims, token, _opts) do
      delete_token(mod, token)
      {:ok, claims}
    end

    @doc """
    Refresh a token
    """
    def refresh(_mod, _old_token, _opts) do
      {:error, :not_refreshable}
    end

    @doc """
    Exchange a token from one type to another
    """
    def exchange(_mod, _old_token, _from_type, _to_type, _opts) do
      {:error, :not_exchangeable}
    end

    defp delete_token(mod, token) do
      q = from(t in mod.token_table, where: t.id == ^token)
      mod.repo.delete_all(q)
    end

    defp find_expiry(mod, claims, opts) when is_list(opts) do
      opts_as_map = Enum.into(opts, %{})
      find_expiry(mod, claims, opts_as_map)
    end

    defp find_expiry(_mod, _claims, %{expiry: exp}) when not is_nil(exp), do: exp

    defp find_expiry(_mod, _claims, %{ttl: ttl}) when not is_nil(ttl), do: expiry_from_ttl(ttl)
    defp find_expiry(mod, _claims, _opts), do: expiry_from_ttl(mod.config(:ttl))

    defp expiry_from_ttl(nil), do: nil

    defp expiry_from_ttl(ttl) do
      ts = DateTime.utc_now() |> DateTime.to_unix()
      sec = ttl_in_seconds(ttl)
      DateTime.from_unix(ts + sec)
    end

    defp ttl_in_seconds({seconds, unit}) when unit in [:seconds, :seconds], do: seconds
    defp ttl_in_seconds({minutes, unit}) when unit in [:minute, :minutes], do: minutes * 60
    defp ttl_in_seconds({hours, unit}) when unit in [:hour, :hours], do: hours * 60 * 60
    defp ttl_in_seconds({weeks, unit}) when unit in [:week, :weeks], do: weeks * 7 * 24 * 60 * 60
    defp ttl_in_seconds({_, units}), do: raise("Unknown Units: #{units}")

    defp find_token(mod, token) do
      query = from(t in {mod.token_table, Token}, where: t.id == ^token)
      mod.repo.one(query)
    end

    defp find_token(mod, token, nil) do
      find_token(mod, token)
    end

    defp find_token(mod, token, expiring_after) do
      query =
        from(
          t in {mod.token_table, Token},
          where: is_nil(t.expiry) or t.expiry >= ^expiring_after,
          where: t.id == ^token
        )
      mod.repo.one(query)
    end
  end
end
