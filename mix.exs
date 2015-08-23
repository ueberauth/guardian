defmodule Guardian.Mixfile do
  use Mix.Project

  @version "0.5.0"

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

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application do
    [applications: [:logger]]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type `mix help deps` for more examples and options
  defp deps do
    ds = [
      {:calendar, "~> 0.9.0"},
      {:joken, "~> 0.15.0"},
      {:poison, "~>1.5"},
      {:ex_doc, "~>0.8"},
    ]

    if Mix.env == :test || Mix.env == :dev do
      [ { :plug, "~> 1.0" } | [ {:ex_doc, "~>0.8"} | [ {:earmark, ">= 0.0.0"} |ds ]]]
    else
      ds
    end
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
