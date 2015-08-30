defmodule Guardian.Mixfile do
  use Mix.Project

  @version "0.6.0"

  def project do
    [
      app: :guardian,
      version: @version,
      elixir: "~> 1.0",
      package: package,
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      contributors: ["Daniel Neighman"],
      description: "Elixir Authentication framework",
      homepage_url: "https://github.com/hassox/guardian",
      docs: [source_ref: "v#{@version}", main: "overview"],
      deps: deps
    ]
  end

  def application do
    [applications: [:logger, :joken, :poison]]
  end

  defp deps do
    [{:joken, "~> 0.15.0"},
     {:poison, "~> 1.5"},
     {:plug, "~> 1.0", only: :test},
     {:ex_doc, "~> 0.8", only: :docs},
     {:earmark, ">= 0.0.0", only: :docs},
     {:uuid, ">=1.0.1"}]
  end

  defp package do
    [
      contributors: ["Daniel Neighman"],
      licenses: ["MIT"],
      links: %{github: "https://github.com/hassox/guardian"},
      files: ~w(lib) ++ ~w(CHANGELOG.md LICENSE mix.exs README.md)
    ]
  end
end
