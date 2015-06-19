use Mix.Config

config :joken,
       secret_key: "lksjdflksjfowieruwoieruowier",
       json_module: Guardian.JWT

config :guardian, Guardian,
      issuer: "MyApp",
      ttl: { 1, :days },
      verify_issuer: true,
      secret_key: "woiuerojksldkjoierwoiejrlskjdf",
      serializer: Guardian.TestGuardianSerializer

