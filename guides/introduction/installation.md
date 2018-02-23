# Installation

To install Guardian, add an entry to your `mix.exs`:

``` elixir
def deps do
  [
    # ...
    {:guardian, "~> 1.0"}
  ]
end
```

## Implementation Module

Guardian requires knowing some information for how you want your token to behave.

By default, Guardian uses [JWT](https://jwt.io/) as the [default token type](Guardian.Token.Jwt.html) but other token types can be used by implementing the [Guardian.Token](Guardian.Token.html) behaviour.

## Configuration

Configuration for Guardian is determined by the Token module that is used and may be extended by other modules.

For default setup please see [the default token docs](tokens-jwt-start.html)

## Plug, Phoenix, and Guardian

Most people use Guardian to support HTTP and Websockets with Phoenix.

Phoenix and Plug are not required but if they are present
Most people use Absinthe to support an HTTP API.

You'll want to read the [Plug](plug-start.html) and [Phoenix](phoenix-start.html) for specific installation and configuration options.
