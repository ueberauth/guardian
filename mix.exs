defmodule Guardian.Mixfile do
  use Mix.Project

  @version "0.13.0"
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
      elixir: "~> 1.3",
      package: package(),
      source_url: @url,
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      maintainers: @maintainers,
      description: "Elixir Authentication framework",
      homepage_url: @url,
      docs: docs(),
      deps: deps(),
      dialyzer: [plt_file: ".dialyzer/local.plt",
                 plt_add_deps: :project]
    ]
  end

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
     {:phoenix, "~> 1.2.0", optional: true},
     {:plug, "~> 1.0"},
     {:poison, ">= 1.3.0"},
     {:uuid, ">=1.1.1"},

     # Dev and Test dependencies
     {:credo, "~> 0.3", only: [:dev, :test]},
     {:dialyxir, "~> 0.3.5", only: [:dev, :test]},
     {:earmark, ">= 0.0.0", only: :dev},
     {:ex_doc, "~> 0.10", only: :dev}]
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
