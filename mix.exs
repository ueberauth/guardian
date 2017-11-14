defmodule Guardian.Mixfile do
  @moduledoc false
  use Mix.Project

  @version "1.0.0-beta.2"
  @url "https://github.com/ueberauth/guardian"
  @maintainers [
    "Daniel Neighman",
    "Sonny Scroggin",
    "Sean Callan",
  ]

  def project do
    [
      name: "Guardian",
      app: :guardian,
      version: @version,
      elixir: "~> 1.4 or ~> 1.5",
      elixirc_paths: elixirc_paths(Mix.env),
      package: package(),
      source_url: @url,
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      maintainers: @maintainers,
      description: "Elixir Authentication framework",
      homepage_url: @url,
      aliases: aliases(),
      docs: docs(),
      deps: deps(),
      xref: [exclude: [:phoenix]],
      dialyzer: [plt_add_deps: :transitive,
                 plt_add_apps: [:mix],
                 flags: [:race_conditions, :no_opaque],
      ]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [applications: [:logger, :poison, :jose, :uuid]]
  end

  def docs do
    [
      extras: ["README.md", "CHANGELOG.md"],
      source_ref: "v#{@version}"
    ]
  end

  defp deps do
    [
      {:jose, "~> 1.8"},
      {:poison, "~> 2.2 or ~> 3.0"},
      {:uuid, ">= 1.1.1"},

      # Optional dependencies
      {:phoenix, "~> 1.0 or ~> 1.2 or ~> 1.3", optional: true},
      {:plug, "~> 1.3.3 or ~> 1.4", optional: true},

      # Dev and Test dependencies
      {:credo, "~> 0.8.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 0.5.0", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.16", only: :dev},

      # Used for the one time token
      {:ecto, "~> 2.2.6", optional: true},
      {:postgrex, "~> 0.13.3", optional: true},
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

  defp aliases do
    [
      # Ensures database is reset before tests are run
      "test": ["ecto.create --quiet", "ecto.migrate", "test"]
    ]
  end
end
