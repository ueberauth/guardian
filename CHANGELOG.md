# Changelog

## v2.5.0

### Added

* The verify plugs accept a one argument function for `:secret`, called with the
  connection to select a verifying secret per request. This covers multitenant
  setups where each tenant has its own key
  ([#690](https://github.com/ueberauth/guardian/issues/690)).

      plug Guardian.Plug.VerifyHeader, secret: &MyApp.Secrets.for_conn/1

  Supported by `Guardian.Plug.VerifyHeader`, `Guardian.Plug.VerifySession` and
  `Guardian.Plug.VerifyCookie`, and exposed as `Guardian.Plug.resolve_secret/2`
  for custom plugs. A `:secret` function of any other arity raises an
  `ArgumentError` instead of reaching the token module.

### Changed

* **Behaviour change.** `Guardian.Token.Jwt.Verify` rejects `exp`, `nbf` and
  `auth_time` claims that are not numbers, and
  `Guardian.Token.Verify.time_within_drift?/2` returns `false` instead of
  `true` for a non-numeric time. Previously a token carrying a string or
  boolean in a time claim passed the drift check and was accepted as valid
  ([#745](https://github.com/ueberauth/guardian/pull/745)).

* **Behaviour change.** `Guardian.Token.Jwt` no longer falls back to the
  implementation module's `:secret_key` when an explicitly provided `:secret`
  is `nil`, or when a `{module, function, args}` secret resolves to `nil`. Both
  now fail with `{:error, :secret_not_found}`. Previously a runtime secret
  lookup that returned `nil` would silently sign or verify with the application
  wide secret, which defeats tenant isolation when third party issued tokens
  and application issued tokens share an implementation module. Omitting
  `:secret` entirely still uses `:secret_key` as before.

* `Guardian.Token.Jwt.decode_token/3` propagates `{:error, :secret_not_found}`
  instead of reporting it as `{:error, :invalid_token}`, so a missing runtime
  secret is distinguishable from a bad signature. Error handlers matching on
  `{:invalid_token, :invalid_token}` for this case should also match
  `{:invalid_token, :secret_not_found}`.

### Documentation

* Document that the verify plugs forward unrecognized options to
  `Guardian.decode_and_verify/4`, including `Guardian.Token.Jwt`'s `:secret`,
  and add a "Runtime secrets" guide covering per-tenant verifying secrets.

## v2.4.1

### Security

* Verify a token's signature in `Guardian.revoke/3` before invoking the token
  module's `revoke` and the implementation's `on_revoke` callbacks. Previously
  the claims were read with `peek/1`, which performs no signature verification,
  allowing a forged token to drive revocation of another session. Claim
  validation such as expiry is still skipped so already expired tokens remain
  revocable (GHSA-7975-hp3r-5qhv / CVE-2026-55735).
* Fix unbounded atom creation in `Guardian.Plug.Keys` (GHSA-xqch-c77q-rgh5 /
  CVE-2026-54894). Deriving a Guardian key from attacker-influenced input no
  longer creates atoms: namespace lookups resolve through
  `String.to_existing_atom/1` (an unknown value reads back as `nil`), atoms are
  only interned on the write path from developer-controlled keys, and session
  and cookie names are derived as strings.
* Fix unbounded atom creation in `Guardian.Permissions.AtomEncoding.encode_value/3`
  (GHSA-fjr5-7xrc-hmpj / CVE-2026-55733). Permission scopes reaching the
  imported `encode/3` entry point are now validated against the configured
  permission set before atom conversion instead of being interned unbounded.
* Fix unbounded atom creation in `Guardian.Permissions.encode_permissions!/1`
  (GHSA-9qx2-v587-q3gg / CVE-2026-55734). Permission-set keys are now
  validated, including integer-valued entries which previously bypassed
  validation entirely, before being converted to atoms.

## v2.4.0

* Add compatibility with Elixir 1.18.0

## v2.3.1

* Change compile time loading of configuration to only load permissions
  allowing the app to change things like ttl or secret key at runtime

## v2.3.0

* Fix warning about the usage of `Application.get_env` in the module scope
* Change Elixir required version to follow https://github.com/ueberauth/.github/blob/master/SECURITY.md#supported-versions

### Enhancement

* Check float values of `time` in `time_within_drift?/2`.

## v2.2.3

### Enhancement

* Ensure that badly-formatted tokens don't raise an exception when attempting to decode them.

## v2.2.2

### Enhancement

* `Guardian.Plug.EnsureAuthenticated` will now accept atom keys in the map passed to the `claims` option.

## v2.2.1

### Enhancement

* `Guardian.Plug.VerifyHeader` and `Guardian.Plug.VerifySession` `:refresh_from_cookie` option will try refreshing
when access token not found, invalid or expired if cookie present [#683](https://github.com/ueberauth/guardian/pull/683)

## v2.2.0

### Enhancement

* Add `:scheme` option to `Guardian.Plug.VerifyHeader` [#680](https://github.com/ueberauth/guardian/pull/680)
* Add `:refresh_from_cookie` option to `Guardian.Plug.VerifyHeader` and `Guardian.Plug.VerifySession`
to replace `Guardian.Plug.VerifyCookie` plug [#675](https://github.com/ueberauth/guardian/pull/675)

### Deprecation

* `:realm` option configuration of `Guardian.Plug.VerifyHeader` is deprecated
  please use `:scheme` instead.
* `Guardian.Plug.VerifyCookie` is deprecated in favor of `:refresh_from_cookie` option in
`Guardian.Plug.VerifyHeader` and `Guardian.Plug.VerifySession`

## v2.1.2

### Enhancement

* Documentation improvements
* Parse the kid from the signing secret to the signature [#654](https://github.com/ueberauth/guardian/pull/654)

### Bugfix
* Fixed issue with remember_me plug not using the correct ttl [#649](https://github.com/ueberauth/guardian/pull/649)
* Fixed failing compilation if plug was not included as a dep [#633](https://github.com/ueberauth/guardian/pull/663)

*Thanks goes to all contributors*


## v2.1.1
### Enhancement
* Documentation improvements

## v2.1.0

### Enhancement

* Add option `halt` to all plugs. This allows to optionally not halt the connection on error so downstream plugs are
  still called [#617](https://github.com/ueberauth/guardian/pull/617)
* Added SlidingCookie plug that allows auto refreshing cookie tokens [616](https://github.com/ueberauth/guardian/pull/616)
* Documentation updates

### Bug Fix

* Error when permissions was an empty list, was causes by a wrong default value, [625](https://github.com/ueberauth/guardian/pull/625)

## v2.0.1

### Enhancement

* Documentation updates

## v2.0.0

### Enhancement

* Improve `Dialyzer` [572](https://github.com/ueberauth/guardian/pull/572)
* Allow ability to verify token in custom header location [597](https://github.com/ueberauth/guardian/pull/597)

### Bug Fix

* Fix `cookie_options` configuration overrides [#570](https://github.com/ueberauth/guardian/pull/570)

### Breaking Change

* Improved `Guardian.Permissions`. Now `Guardian.Permissions` accepts multiple
  encoders. The interface is defined in `Guardian.Permissions.PermissionEncoding`. [585](https://github.com/ueberauth/guardian/pull/585)

  To fix the breaking changes, do something as follow.

  1. Find `use Guardian.Permissions.Bitwise`
  2. Replace with `use Guardian.Permissions, encoding: Guardian.Permissions.BitwiseEncoding`

  Notice that we added a key called `encoding`, this key will allow you pass
  the encoding strategy that fit yours needs.

  Check the list of supported encoding.

  * `Guardian.Permissions.BitwiseEncoding`
  * `Guardian.Permissions.AtomEncoding`
  * `Guardian.Permissions.TextEncoding`

* Moved `Guardian.Phoenix.Socket` to [guardian_phoenix](https://github.com/ueberauth/guardian_phoenix).
  You should be install `guardian_phoenix` and it should work as today.

## v1.1.0

* JWT secret fetcher behaviour added
* Let Guardian plug call :revoke on sign_out [#458](https://github.com/ueberauth/guardian/pull/458)
* Fix an issue where Guardian.Plug tries to clear the wrong keys from the conn [#476](https://github.com/ueberauth/guardian/pull/476)

## v1.0.0

* Allow for multiple Guardian setups in a single applications
* Adds pipelines
* Significantly updates Guardian api to be more consistent
* Make Phoenix an optional dependency
* Make Plug an optional dependency
* Permissions as an optional add-in
* Deprecates Hooks in favour of callbacks on particular implementations
* Removes Phoenix macros in favour of plain functions

See the [0.14 to 1.0 Upgrade Guide](upgrade_guides/0.14.to.1.0.md) for detailed updating instructions

## v0.14.5

Update the poison and phoenix deps to allow a broader version setting

## v0.14.4

* Fix a param issue in sockets

## v0.14.3

* Fix function specs
* Renew session on `sign_in`
* Add a custom claim key from load resource

## v0.14.2

* __Really_ fix pattern matching error with GuardianDB

## v0.14.1

* Fixed pattern matching error with GuardianDB

## v0.14.0

* Update to Elixir 1.3
* Added test coverage: https://github.com/ueberauth/guardian/pull/234
* Token exchange: https://github.com/ueberauth/guardian/pull/150
* Adds ensure resource plug https://github.com/ueberauth/guardian/pull/238
* Name collision fix: https://github.com/ueberauth/guardian/pull/215
* Support for `{:system, var}` configuration options
* Adds an `allowed_drift` option to allow for clock skew

### Bugs

* Replaced taking a function for configuring secret_key with accepting a tuple {mod, func, args}

## v0.13.0

* Change default token type from "token" to "access"
* Fix Dialyzer errors
* Target Elixir 1.3+
* Update Jose and Phoenix dependencies
* Fixes for ttl and exp
* Added integration tests

## v0.12.0
* Add `one_of` to permissions Plug to allow for OR'd sets of permissions as well as AND'd ones
* Fix infinite recursion bug when joining channels

## v0.11.1

* Support for secret keys other than "oct" which provides support for signature
  algorithms other than HSxxx. See #122
* Fix incorrect param name in channel
* Tighten up log calls
* Fix moar typos
* General code cleanup
* Loosen poison requirement to >= 1.3.0
* Use existing resource on conn if already present
* Fix refresh to correctly use revoke

## v0.10.1

* Fix error in Guardian.Plug.ErrorHandler when Accept header is unset.
* Adding Guardian.Plug.EnsureNotAuthenticated to validates that user isn't logged
* Fix bug where TTL was not able to be set when generating tokens

## v0.10.0

* Add a Guardian.Phoenix.Socket module and refactor Guardian.Channel
* Update JOSE to Version 1.6.0. Version 1.6.0 of erlang-jose
adds the ability of using libsodium and SHA-3 (keccack) algorithms.
This improves speed a lot.
* Adds Travis
* Adds ability to use custom secrets
* Allows peeking at the contents of the token

## v0.9.1

* Stop compiling permissions. This leads to weird bugs when permissions are
  changed but not recompiled

## v0.9.0

* Remove internal calls to Dict
* Store the type of the token in the typ field rather than the aud field
  The aud field should default to the sub or failing that, the iss.
  This is to facilitate implementing an OAuth provider or just allowing
  folks to declare their own audience.

## v0.8.1

* Fix a bug with logout where it was not checking the session, only the assigns
  This meant that if you had not verified the session the token would not be
  revoked.

## v0.7.1

* Adds basic Phoenix controller helpers

## v0.7.0

* Remove Joken from the dependencies and use JOSE instead.
* Add a refresh! function

## v0.6.2

* Adds Guardian.Plug.authenticated?
* Adds simple claim checks to EnsureAuthenticated

### Bugs

* Fix an issue with permissions strings vs atoms (not encoding correctly)

## v0.6.0
Rename

    Guardian.mint -> Guardian.encode_and_sign
    Guardian.verify -> Guardian.decode_and_verify

    Guardian.Plug.EnsureSession -> Guardian.Plug.EnsureAuthenticated
    Guardian.Plug.VerifyAuthorization -> Guardian.Plug.VerifyHeader

## v0.5.2

Add new hooks on\_verify and on\_revoke
Remove multiple hooks registration

## v0.5.1

Allow multiple hooks to be registered to Guardian

## v0.5.0

Use strings for keys in the token.

## v0.4.0

Remove CSRF tokens support. CSRF tokens are masked and so cannot be adequately
implemented.

## v0.3.0

* Add callback hooks for authentication things

## v0.2.0

* Update to use new Joken
* Include permissions

## v0.0.1

Initial Release
