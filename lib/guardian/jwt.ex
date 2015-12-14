defmodule Guardian.JWT do
  @moduledoc false
  @behaviour Guardian.ClaimValidation

  use Guardian.ClaimValidation

  def validate_claim(_, _, _), do: :ok
end
