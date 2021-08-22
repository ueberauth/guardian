defmodule Guardian.Mixfile do
  @moduledoc false
  use Mix.Project

  @version "2.2.1"
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
      dialyzer: dialyxir(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        docs: :docs,
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
      main: "readme",
      extra_section: "guides",
      assets: "guides/assets",
      formatters: ["html", "epub"],
      groups_for_modules: groups_for_modules(),
      extras: extras(),
      groups_for_extras: groups_for_extras()
    ]
  end

  defp dialyxir do
    [
      plt_add_deps: :transitive,
      plt_add_apps: [:mix],
      flags: [:race_conditions, :no_opaque]
    ]
  end

  defp extras do
    [
      "README.md": [
        title: "Readme"
      ],
      "guides/introduction/overview.md": [
        filename: "introduction-overview"
      ],
      "guides/introduction/installation.md": [
        filename: "introduction-installation"
      ],
      "guides/introduction/implementation.md": [
        filename: "introduction-implementation",
        title: "Implementation Modules"
      ],
      "guides/introduction/community.md": [
        filename: "introduction-community"
      ],
      "guides/tutorial/start-tutorial.md": [
        filename: "tutorial-start",
        title: "Getting Started with Guardian"
      ],
      "guides/tokens/start-tokens.md": [
        filename: "tokens-start",
        title: "Start"
      ],
      "guides/tokens/jwt/start.md": [
        filename: "tokens-jwt-start",
        title: "Start"
      ],
      "guides/plug/start-plug.md": [
        filename: "plug-start",
        title: "Start"
      ],
      "guides/plug/pipelines.md": [
        filename: "plug-pipelines",
        title: "Pipelines"
      ],
      "guides/phoenix/start-phoenix.md": [
        filename: "phoenix-start",
        title: "Start"
      ],
      "guides/permissions/start-permissions.md": [
        filename: "permissions-start",
        title: "Start"
      ],
      "guides/upgrading/v1.0.md": [
        filename: "upgrading-v1.0"
      ]
    ]
  end

  defp groups_for_extras do
    [
      Introduction: Path.wildcard("guides/introduction/*.md"),
      Tutorial: Path.wildcard("guides/tutorial/*.md"),
      Tokens: Path.wildcard("guides/tokens/*.md"),
      "JWT Tokens": Path.wildcard("guides/tokens/jwt/*.md"),
      Plug: Path.wildcard("guides/plug/*.md"),
      Phoenix: Path.wildcard("guides/phoenix/*.md"),
      Permissions: Path.wildcard("guides/permissions/*.md"),
      "Upgrade Guides": Path.wildcard("guides/upgrading/*.md")
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
        Guardian.Plug.SlidingCookie,
        Guardian.Plug.Keys
      ],
      Permissions: [
        Guardian.Permissions,
        Guardian.Permissions.PermissionEncoding,
        Guardian.Permissions.BitwiseEncoding,
        Guardian.Permissions.AtomEncoding,
        Guardian.Permissions.TextEncoding
      ]
    ]
  end

  defp deps do
    [
      {:jose, "~> 1.8"},

      # Optional dependencies
      {:plug, "~> 1.3.3 or ~> 1.4", optional: true},

      # Tools
      {:credo, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:dialyxir, ">= 1.0.0-rc4", only: [:dev], runtime: false},
      {:ex_doc, ">= 0.0.0", only: [:dev], runtime: false},
      {:excoveralls, ">= 0.0.0", only: [:test], runtime: false},
      {:inch_ex, ">= 0.0.0", only: [:dev], runtime: false},
      {:jason, "~> 1.1", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      maintainers: @maintainers,
      licenses: ["MIT"],
      links: %{
        Changelog: "https://hexdocs.pm/guardian/changelog.html",
        GitHub: @url
      },
      files: ~w(lib CHANGELOG.md LICENSE mix.exs README.md)
    ]
  end
end
