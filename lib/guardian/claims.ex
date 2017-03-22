defmodule Guardian.Claims do
  @moduledoc false
  import Guardian.Utils

  @doc false
  def app_claims, do: %{"iss" => Guardian.issuer} |> iat |> jti

  @doc false
  def app_claims(existing_claims) do
    Map.merge(app_claims(), Enum.into(existing_claims, %{}))
  end

  @doc """
  Encodes permissions into the claims set.
  Permissions are stored at the :pem key as a map of <type> => <value as int>
  """
  def permissions(claims, perm_list) do
    perms = %{}
    |> Enum.into(perm_list)
    |> Enum.reduce(%{}, fn({key, list}, acc) ->
      Map.put(
        acc,
        to_string(key),
        Guardian.Permissions.to_value(list, key)
      )
    end)
    Map.put(claims, "pem", perms)
  end

  @doc false
  def typ(claims, nil), do: typ(claims, Guardian.default_token_type)
  @doc false
  def typ(claims, type) when is_atom(type), do: typ(claims, to_string(type))
  @doc false
  def typ(claims, type), do: Map.put(claims, "typ", type)

  @doc false
  def aud(claims, nil), do: aud(claims, Guardian.config(:issuer))
  @doc false
  def aud(claims, audience) when is_atom(audience) do
    aud(claims, to_string(audience))
  end

  @doc false
  def aud(claims, audience), do: Map.put(claims, "aud", audience)

  @doc false
  def sub(claims, subject) when is_atom(subject) do
    sub(claims, to_string(subject))
  end

  @doc false
  def sub(claims, subject), do: Map.put(claims, "sub", subject)

  @doc false
  def jti(claims), do: jti(claims, UUID.uuid4)
  @doc false
  def jti(claims, id) when is_atom(id), do: sub(claims, to_string(id))
  @doc false
  def jti(claims, id), do: Map.put(claims, "jti", id)

  @doc false
  def nbf(claims), do: Map.put(claims, "nbf", timestamp() - 1)
  @doc false
  def nbf(claims, ts), do: Map.put(claims, "nbf", ts)

  @doc false
  def iat(claims), do: Map.put(claims, "iat", timestamp())
  @doc false
  def iat(claims, ts), do: Map.put(claims, "iat", ts)

  @doc false
  def ttl(claims = %{"exp" => _exp}), do: claims

  @doc false
  def ttl(claims = %{"ttl" => requested_ttl}) do
    claims
    |> Map.delete("ttl")
    |> ttl(requested_ttl)
  end

  @doc false
  def ttl(claims = %{"typ" => token_typ}) do
    ttl_map = Guardian.config(:token_ttl, %{})
    case ttl_map |> Map.fetch(token_typ) do
      {:ok, token_ttl} ->  ttl(claims, token_ttl)
      :error -> ttl(claims, Guardian.config(:ttl, {1_000_000_000, :seconds}))
    end
  end

  @doc false
  def ttl(claims) do
    ttl_map = Guardian.config(:token_ttl, %{})
    case ttl_map |> Map.fetch("access") do
      {:ok, token_ttl} ->  ttl(claims, token_ttl)
      :error -> ttl(claims, Guardian.config(:ttl, {1_000_000_000, :seconds}))
    end
  end

  @doc false
  def ttl(the_claims, {num, period}) when is_binary(num) do
    ttl(the_claims, {String.to_integer(num), period})
  end

  @doc false
  def ttl(the_claims, {num, period}) when is_binary(period) do
    ttl(the_claims, {num, String.to_existing_atom(period)})
  end

  @doc false
  def ttl(%{"iat" => iat_v} = the_claims, requested_ttl) do
    assign_exp_from_ttl(the_claims, {iat_v, requested_ttl})
  end

  @doc false
  def ttl(the_claims, requested_ttl) do
    the_claims
    |> iat
    |> ttl(requested_ttl)
  end

  defp assign_exp_from_ttl(the_claims, {nil, _}) do
    Map.put_new(the_claims, "exp", timestamp() + 1_000_000_000)
  end

  defp assign_exp_from_ttl(the_claims, {iat_v, {millis, unit}})
  when unit in [:milli, :millis] do
    Map.put(the_claims, "exp", iat_v + millis / 1000)
  end

  defp assign_exp_from_ttl(the_claims, {iat_v, {seconds, unit}})
  when unit in [:second, :seconds] do
    Map.put(the_claims, "exp", iat_v + seconds)
  end

  defp assign_exp_from_ttl(the_claims, {iat_v, {minutes, unit}})
  when unit in [:minute, :minutes] do
    Map.put(the_claims, "exp", iat_v + minutes * 60)
  end

  defp assign_exp_from_ttl(the_claims, {iat_v, {hours, unit}})
  when unit in [:hour, :hours] do
    Map.put(the_claims, "exp", iat_v + hours * 60 * 60)
  end

  defp assign_exp_from_ttl(the_claims, {iat_v, {days, unit}})
  when unit in [:day, :days] do
    Map.put(the_claims, "exp", iat_v + days * 24 * 60 * 60)
  end

  defp assign_exp_from_ttl(the_claims, {iat_v, {years, unit}})
  when unit in [:year, :years] do
    Map.put(the_claims, "exp", iat_v + years * 365 * 24 * 60 * 60)
  end

  defp assign_exp_from_ttl(_, {_iat_v, {_, units}}) do
    raise "Unknown Units: #{units}"
  end

  defp assign_exp_from_ttl(the_claims, _), do: the_claims

end