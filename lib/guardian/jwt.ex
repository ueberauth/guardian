defmodule Guardian.JWT do
  @moduledoc false
  @bahaviour Guardian.ClaimValiation

  use Guardian.ClaimValidation

  def validate_claim(_, _, _), do: :ok
end
