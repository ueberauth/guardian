defmodule Guardian.Encoder.JWTTest do
  @moduledoc false
  use ExUnit.Case, async: true

  test "peeking at the headers" do
    secret = "ABCDEF"
    {:ok, jwt, _} = Guardian.encode_and_sign(
      "thinger",
      "my_type",
      some: "thing",
      secret: secret,
      headers: %{"foo" => "bar"}
    )

    header = Guardian.Encoder.JWT.peek_header(jwt)
    assert header["foo"] == "bar"
  end

  test "peeking at the payload" do
    secret = "ABCDEF"
    {:ok, jwt, _} = Guardian.encode_and_sign(
      "thinger",
      "my_type",
      some: "thing",
      secret: secret,
      headers: %{"foo" => "bar"}
    )

    header = Guardian.Encoder.JWT.peek_claims(jwt)
    assert header["some"] == "thing"
  end

end
