defmodule Guardian.Mixfile do
  @moduledoc false
  use Mix.Project

  @version "1.1.0"
  @url "https://github.com/ueberauth/guardian"
  @maintainers [
    "Daniel Neighman",
    "Sonny Scroggin",
    "Sean Callan"
  ]

  def project do
    [
      name: "Guardian",
      app: :guardian,
      version: @version,
      elixir: "~> 1.4 or ~> 1.5",
      elixirc_paths: elixirc_paths(Mix.env()),
      package: package(),
      source_url: @url,
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      maintainers: @maintainers,
      description: "Elixir Authentication framework",
      homepage_url: @url,
      docs: docs(),
      deps: deps(),
      xref: [exclude: [:phoenix]],
      dialyzer: [
        plt_add_deps: :transitive,
        plt_add_apps: [:mix],
        flags: [:race_conditions, :no_opaque]
      ],
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.html": :test
      ]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [extra_applications: [:crypto, :logger]]
  end

  def docs do
    [
      source_ref: "v#{@version}",
      main: "introduction-overview",
      extra_section: "guides",
      assets: "guides/assets",
      formatters: ["html", "epub"],
      groups_for_modules: groups_for_modules(),
      extras: extras()
    ]
  end

  defp extras do
    [
      "guides/introduction/overview.md": [
        group: "Introduction",
        filename: "introduction-overview"
      ],
      "guides/introduction/installation.md": [
        group: "Introduction",
        filename: "introduction-installation"
      ],
      "guides/introduction/implementation.md": [
        group: "Introduction",
        filename: "introduction-implementation",
        title: "Implementation Modules"
      ],
      "guides/introduction/community.md": [
        group: "Introduction",
        filename: "introduction-community"
      ],
      "guides/tutorial/start-tutorial.md": [
        group: "Tutorial",
        filename: "tutorial-start",
        title: "Start"
      ],
      "guides/tokens/start-tokens.md": [group: "Tokens", filename: "tokens-start", title: "Start"],
      "guides/tokens/jwt/start.md": [
        group: "JWT Tokens",
        filename: "tokens-jwt-start",
        title: "Start"
      ],
      "guides/plug/start-plug.md": [group: "Plug", filename: "plug-start", title: "Start"],
      "guides/plug/pipelines.md": [group: "Plug", filename: "plug-pipelines", title: "Pipelines"],
      "guides/phoenix/start-phoenix.md": [
        group: "Phoenix",
        filename: "phoenix-start",
        title: "Start"
      ],
      "guides/permissions/start-permissions.md": [
        group: "Permissions",
        filename: "permissions-start",
        title: "Start"
      ],
      "guides/upgrading/v1.0.md": [group: "Upgrade Guides", filename: "upgrading-v1.0"]
    ]
  end

  defp groups_for_modules do
    # Ungrouped:
    # - Guardian

    [
      Tokens: [
        Guardian.Token,
        Guardian.Token.Verify,
        Guardian.Token.Jwt,
        Guardian.Token.Jwt.Verify
      ],
      Plugs: [
        Guardian.Plug,
        Guardian.Plug.Pipeline,
        Guardian.Plug.EnsureAuthenticated,
        Guardian.Plug.EnsureNotAuthenticated,
        Guardian.Plug.LoadResource,
        Guardian.Plug.VerifySession,
        Guardian.Plug.VerifyHeader,
        Guardian.Plug.VerifyCookie,
        Guardian.Plug.Keys
      ],
      Phoenix: [
        Guardian.Phoenix.Socket
      ],
      Permissions: [
        Guardian.Permissions.Bitwise
      ]
    ]
  end

  defp deps do
    [
      {:jose, "~> 1.8"},
      {:poison, "~> 2.2 or ~> 3.0"},

      # Optional dependencies
      {:phoenix, "~> 1.0 or ~> 1.2 or ~> 1.3", optional: true},
      {:plug, "~> 1.3.3 or ~> 1.4", optional: true},

      # Tools
      {:dialyxir, ">= 0.0.0", only: [:dev], runtime: false},
      {:credo, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:excoveralls, ">= 0.0.0", only: [:test], runtime: false},
      {:ex_doc, ">= 0.0.0", only: [:dev], runtime: false},
      {:inch_ex, ">= 0.0.0", only: [:dev], runtime: false}
    ]
  end

  defp package do
    [
      maintainers: @maintainers,
      licenses: ["MIT"],
      links: %{github: @url},
      files: ~w(lib) ++ ~w(CHANGELOG.md LICENSE mix.exs README.md)
    ]
  end
end
