defmodule Guardian.UtilsTest do
  use ExUnit.Case, async: true

  test "stringify_keys" do
    assert Guardian.Utils.stringify_keys(%{ foo: "bar" }) == %{ "foo" => "bar" }
  end

  test "timestamp" do
    assert Guardian.Utils.timestamp == Calendar.DateTime.now_utc |> Calendar.DateTime.Format.unix
  end
end
