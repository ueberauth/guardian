defmodule Guardian.Support.Utils do
  @moduledoc """
  Provides some helper functions to help with testing
  """

  def send_function_call(call) do
    send(self(), call)
  end

  def gather_function_calls, do: gather_function_calls([])

  def gather_function_calls(list) do
    receive do
      {_, _, _} = call -> gather_function_calls([call | list])
    after
      0 -> Enum.reverse(list)
    end
  end
end
