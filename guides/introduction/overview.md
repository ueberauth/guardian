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

## Guides

To contribute to the guides, please submit a pull request to the [guardian](https://github.com/ueberauth/guardian) project on GitHub.

You'll find the content under `guides/`.
