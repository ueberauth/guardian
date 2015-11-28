defmodule Guardian.Mixfile do
  use Mix.Project

  @version "0.7.4"

  def project do
    [
      app: :guardian,
      version: @version,
      elixir: "~> 1.1",
      package: package,
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      maintainers: ["Daniel Neighman"],
      description: "Elixir Authentication framework",
      homepage_url: "https://github.com/hassox/guardian",
      docs: [source_ref: "v#{@version}", main: "overview"],
      deps: deps
    ]
  end

  def application do
    [applications: [:logger, :poison, :jose, :uuid]]
  end

  defp deps do
    [{:jose, "~> 1.4"},
     {:poison, "~> 1.5"},
     {:plug, "~> 1.0"},
     {:ex_doc, "~> 0.10", only: :docs},
     {:earmark, ">= 0.0.0", only: :docs},
     {:uuid, ">=1.1.1"}]
  end

  defp package do
    [
      maintainers: ["Daniel Neighman"],
      licenses: ["MIT"],
      links: %{github: "https://github.com/hassox/guardian"},
      files: ~w(lib) ++ ~w(CHANGELOG.md LICENSE mix.exs README.md)
    ]
  end
end
