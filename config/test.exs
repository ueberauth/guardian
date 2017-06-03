use Mix.Config


config :phoenix, format_encoders: [json: Poison]

config :guardian, GuardianPhoenix.ControllerTest.Endpoint,
  secret_key_base: "lksdjfl"

config :guardian, GuardianPhoenix.SocketTest.Impl,
  stuff: "and things"
