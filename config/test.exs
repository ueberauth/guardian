use Mix.Config

config :guardian, Guardian,
      issuer: "MyApp",
      allowed_algos: ["HS512", "ES512"],
      ttl: { 1, :days },
      refresh_ttl: { 1, :years },
      verify_issuer: true,
      secret_key: "woiuerojksldkjoierwoiejrlskjdf",
      serializer: Guardian.TestGuardianSerializer,
      permissions: %{
        default: [:read, :write, :update, :delete],
        other: [:other_read, :other_write, :other_update, :other_delete]
      }
