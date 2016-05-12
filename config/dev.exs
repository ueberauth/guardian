use Mix.Config

config :guardian, Guardian,
      issuer: "MyApp",
      ttl: { 1, :days },
      refresh_ttl: { 1, :years },
      verify_issuer: true,
      secret_key: "woiuerojksldkjoierwoiejrlskjdf",
      serializer: Guardian.TestGuardianSerializer
