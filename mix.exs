defmodule Guardian.Mixfile do
  use Mix.Project

  @version "0.8.1"
  @url "https://github.com/ueberauth/guardian"
  @maintainers ["Daniel Neighman", "Sonny Scroggin", "Sean Callan"]

  def project do
    [
      app: :guardian,
      version: @version,
      elixir: "~> 1.1",
      package: package,
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      maintainers: @maintainers,
      description: "Elixir Authentication framework",
      homepage_url: @url,
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
      maintainers: @maintainers,
      licenses: ["MIT"],
      links: %{github: @url},
      files: ~w(lib) ++ ~w(CHANGELOG.md LICENSE mix.exs README.md)
    ]
  end
end
