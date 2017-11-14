use Mix.Config

config :plug, validate_header_keys_during_test: true

config :phoenix, format_encoders: [json: Poison]

config :guardian, Guardian.Phoenix.ControllerTest.Endpoint,
  secret_key_base: "lksdjfl"

config :guardian, Guardian.Phoenix.SocketTest.Impl, []

config :guardian, Guardian.Phoenix.Permissions.BitwiseTest.Impl, []


config :guardian, ecto_repos: [Guardian.Token.OneTime.Repo]

config :guardian, Guardian.Token.OneTime.Repo,
  adapter: Ecto.Adapters.Postgres,
  username: "postgres",
  database: "guardian_one_time_test",
  hostname: "localhost",
  pool: Ecto.Adapters.SQL.Sandbox,
  loggers: []
