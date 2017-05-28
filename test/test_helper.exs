defmodule Guardian.TestHelper do
  @moduledoc false
  defmacro __using__(_ \\ []) do
    quote do
      def subject_for_token(%{id: id}, _claims), do: {:ok, id}
      def subject_for_token(%{"id" => id}, _claims), do: {:ok, id}

      def resource_from_claims(%{"sub" => id}), do: {:ok, %{id: id}}
    end
  end
end

ExUnit.start()
