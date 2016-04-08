defmodule Guardian.Mixfile do
  use Mix.Project

  @version "0.10.1"
  @url "https://github.com/ueberauth/guardian"
  @maintainers [
    "Daniel Neighman",
    "Sonny Scroggin",
    "Sean Callan",
    "Aaron Renner"
  ]

  def project do
    [
      name: "Guardian",
      app: :guardian,
      version: @version,
      elixir: "~> 1.1",
      package: package,
      source_url: @url,
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      maintainers: @maintainers,
      description: "Elixir Authentication framework",
      homepage_url: @url,
      docs: docs,
      deps: deps
    ]
  end

  def application do
    [applications: [:logger, :poison, :jose, :uuid]]
  end

  def docs do
    [
      extras: ["README.md", "CHANGELOG.md"],
      source_ref: "v#{@version}",
      main: "extra-readme"
    ]
  end

  defp deps do
    [{:jose, "~> 1.6"},
     {:poison, ">= 1.3.0 and < 3.0.0"},
     {:plug, "~> 1.0"},
     {:ex_doc, "~> 0.10", only: :docs},
     {:earmark, ">= 0.0.0", only: :docs},
     {:credo, "~> 0.3", only: [:dev, :test]},
     {:uuid, ">=1.1.1"}]
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
