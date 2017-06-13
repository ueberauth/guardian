defmodule Guardian.Mixfile do
  use Mix.Project

  @version "1.0.0-rc.1"
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
      elixir: ">= 1.3.2 or ~> 1.4",
      elixirc_paths: elixirc_paths(Mix.env),
      package: package(),
      source_url: @url,
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      maintainers: @maintainers,
      description: "Elixir Authentication framework",
      homepage_url: @url,
      docs: docs(),
      deps: deps(),
      xref: [exclude: [:phoenix]],
      dialyzer: [plt_add_deps: :project]
    ]
  end

  defp elixirc_paths(env) when env in [:test], do: ["lib", "test/support"]
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
    [{:jose, "~> 1.8"},
     {:plug, ">= 1.0.0", optional: true},
     {:poison, ">= 1.3.0 and < 4.0.0"},
     {:uuid, ">= 1.1.1"},
     {:phoenix, ">= 1.0.0 and < 2.0.0", optional: true},

     # Dev and Test dependencies
     {:credo, "~> 0.8.0-rc6", optional: true, runtime: false},
     {:dialyxir, "~> 0.5.0", optional: true, only: [:dev, :test], runtime: false},
     {:ex_doc, "~> 0.15", optional: true, only: :dev}]
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
