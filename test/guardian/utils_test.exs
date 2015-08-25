defmodule Guardian.UtilsTest do
  use ExUnit.Case, async: true

  test "stringify_keys" do
    assert Guardian.Utils.stringify_keys(%{ foo: "bar" }) == %{ "foo" => "bar" }
  end

  test "timestamp" do
    {mgsec, sec, _usec} = :os.timestamp
    assert Guardian.Utils.timestamp == mgsec * 1_000_000 + sec
  end
end
