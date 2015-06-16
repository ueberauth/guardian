Guardian
========

An authentication framework for use with Elixir applications.

Guardian is based on similar ideas to Warden and Omniauth but is re-imagined
for modern systems where Elixir manages the authentication requrements.

Guardian can interoperate with many systems and aims to provide:

* Flexible serialization
* Flexible strategy based authentication
* Two-factor authentication
* Sevice2Service credentials. That is, pass the authentication results through many downstream requests.
* Integrated permission sets
* Integration with Plug
* Integration with Phoenix channels
* Basic integrations like raw TCP

Would be great to provide:

* Single sign-in
* Device specific signing

Guardian remains a functional system. It integrates with Plug, but can be used
outside of it. If you're implementing a TCP/UDP protocol directly, or want to
utilize your authentication via channels, Guardian is your operative.

## Low level API

    # Generate a JWT for use as a credential either stored in the session
    # Or passed as an authentication header
    # @param <Map> - claims, The claims the token asserts are true.
    jwt = Guardian.mint(claims, :csrf, %{ csrf: "LKSJDFLKJD" })

    # Verify a JWT for consumption
    case Guardian.verify(jwt) do
      { :ok, claims } -> do_stuff_with(claims, params)
      { :error, reason } -> do_stuff_with_errors(reason)
    end

    # Verify a JWT and raise
    claims = Guardian.verify!(jwt, params)

This implies that somehow we've verified those claims when they were minted.
There are too many ways to verify these to go through, but we can provide some assistance when Plug is concerned.

## Plug API

When you're using plug, we have a short plug stack that injects the conn object
with set of claims, and a JWT. There is also a plug that will ensure that you
have a valid token, and that you have the relevant permissions.There are too
many ways to verify these to go through, but we can provide some assistance when
Plug is concerned.

    pipeline :browser do
      plug Guardian.Plug.FromSession
      plug Guardian.Plug.FromApiToken, realm: "Bearer"
    end

In your controller:

    plug Guardian.Plug.Enforcer, type: :web

We split the guarding into two portions.

1. The token fetcher
2. The enforcer

The token fetcher finds tokens from various places within the request, verifies
that it is valid, and stores the result on the connection.
It can limit based on token type, or permissions.

The enforcer requires that there is a valid token and will prevent further
processing if there is not.:w




