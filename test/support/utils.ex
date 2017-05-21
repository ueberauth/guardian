defmodule Guardian.Support.Utils do
  @moduledoc """
  Provides some helper functions to help with testing
  """

  @method_regex ~r/^[A-Z][a-z0-9A-Z\.]+\.[a-z][a-z_0-9]+\(.*?\)$/m

  def filter_function_calls(io_calls) when is_binary(io_calls) do
    io_calls
    |> String.split("\n")
    |> filter_function_calls()
  end

  def filter_function_calls(io_calls) do
    Enum.filter(io_calls, &(String.match?(&1, @method_regex)))
  end

  def args_to_string(args) when is_binary(args), do: args
  def args_to_string(args) when is_list(args) do
    args
    |> Enum.map(&(inspect(&1)))
    |> Enum.join(", ")
  end

  def print_function_call({m, f, a}) do
    args = args_to_string(a)
    IO.puts("#{inspect(m)}.#{to_string(f)}(#{args})")
  end
end
