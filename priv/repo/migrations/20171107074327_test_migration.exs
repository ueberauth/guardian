defmodule Guardian.OneTime.Repo.Migrations.TestMigration do
  use Ecto.Migration

  def change do
    create table(:one_time_tokens, primary_key: false) do
      add :id, :string, priary_key: true
      add :claims, :map
      add :expiry, :utc_datetime
    end
  end
end
