# Overview

Guardian is the authentication toolkit for Elixir. It provides token based authentication. It does not provide implementations for the challenge phase (the first verification of the resource/user) built to suit Elixir idioms.

To perform the challenge phase of authentication you can use [Ueberauth](https://github.com/ueberauth/ueberauth) to help you or use whatever methodology makes sense for your application.

## Defaults

The default token type for Guardian is JWT. This is not fixed. Guardian can use any token that conforms to the [Guardian.Token](Guardian.Token.html) behaviour.

JWT is a reasonable default that can be used in most situations including browser, mobile, 3rd party services over any communication channel. If you can get a token to your application, Guardian can use it.

## Guardian

Guardians functionality has two core pieces.

* Creating Tokens
* Verifying tokens

It also provides

* [Custom Tokens](tokens-start.html)
* [Plug integration](plug-start.html)
* [Phoenix integration](phoenix-start.html)
* [Permissions](permissions-start.html)

## Tokens in your application

Guardian provides behaviours so that different implementations can be created.

For example you could have two token types for different purposes both backed by the default (JWT).

```elixir
defmodule MyApp.TokenModuleOne do
  use Guardian, otp_app: :my_app

  # ...
end

defmodule MyApp.TokenModuleTwo do
  use Guardian, otp_app: :my_app

  # ...
end
```

By allowing different modules to be implemented you can have multiple configurations inside your application for different purposes.

Token implementations are provided via an adapter pattern. By implementing the [Guardian.Token](Guardian.Token.html) behaviour your backend can be implemented any way you need, and specified in your configuration via the `token_module` option as either an option to the `use` call or in your configuration.

```elixir
defmodule MyApp.TokenModuleCustom do
  use Guardian, otp_app: :my_app,
      token_module: MyApp.CusomTokenBackend

  # ...
end
```

or via configuration

```elixir
defmodule MyApp.TokenModuleCustom do
  use Guardian, otp_app: :my_app

  # ...
end
```

```elixir
use Mix.Config

config :my_app, MyApp.TokenModuleCustom,
  token_module: MyApp.CustomTokenBackend
```

All configuration for your implementation module can be done this way - either via arguments to `use` or inside configuration.

Check the [implementation module docs](introduction-implementation.html) for more information.

# Tutorials

* [Getting started](tutorial-start.html)

## Guides

To contribute to the guides, please submit a pull request to the [guardian](https://github.com/ueberauth/guardian) project on GitHub.

You'll find the content under `guides/`.
