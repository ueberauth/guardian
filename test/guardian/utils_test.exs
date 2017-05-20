defmodule Guardian.UtilsTest do
  @moduledoc false
  use ExUnit.Case, async: true

  test "Guardian.stringify_keys" do
    assert Guardian.Utils.Guardian.stringify_keys(nil) == %{}
    assert Guardian.Utils.Guardian.stringify_keys(%{foo: "bar"}) == %{"foo" => "bar"}
    assert Guardian.Utils.Guardian.stringify_keys(%{"foo" => "bar"}) == %{"foo" => "bar"}
  end

  test "timestamp" do
    {mgsec, sec, _usec} = :os.timestamp
    assert Guardian.Utils.timestamp == mgsec * 1_000_000 + sec
  end
end
