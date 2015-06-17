use Mix.Config

config :joken,
       secret_key: "lksjdflksjfowieruwoieruowier",
       json_module: Guardian.Jwt

config :guardian, Guardian,
      issuer: "MyApp",
      ttl: { 1, :days },
      verify_issuer: true,
      serializer: Guardian.TestGuardianSerializer

