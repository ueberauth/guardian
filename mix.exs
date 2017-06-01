defmodule Guardian.Mixfile do
  use Mix.Project

  @version "0.14.4"
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
     {:phoenix, "~> 1.2", optional: true},
     {:plug, "~> 1.3"},
     {:poison, ">= 1.3.0"},
     {:uuid, ">=1.1.1"},

     # Dev and Test dependencies
     {:credo, "~> 0.6.1", only: [:dev, :test]},
     {:dialyxir, "~> 0.4.3", only: [:dev, :test]},
     {:earmark, ">= 0.0.0", only: :dev},
     {:ex_doc, "~> 0.12", only: :dev}]
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
