# v 0.14.4

* Fix a param issue in sockets

# v 0.14.3

* Fix function specs
* Renew session on `sign_in`
* Add a custom claim key from load resource

# v 0.14.2

* __Really_ fix pattern matching error with GuardianDB

# v 0.14.1

* Fixed pattern matching error with GuardianDB

# v 0.14.0

* Update to Elixir 1.3
* Added test coverage: https://github.com/ueberauth/guardian/pull/234
* Token exchange: https://github.com/ueberauth/guardian/pull/150
* Adds ensure resource plug https://github.com/ueberauth/guardian/pull/238
* Name collision fix: https://github.com/ueberauth/guardian/pull/215
* Support for `{:system, var}` configuration options
* Adds an `allowed_drift` option to allow for clock skew

### Bugs

* Replaced taking a function for configuring secret_key with accepting a tuple {mod, func, args}

# v 0.13.0

* Change default token type from "token" to "access"
* Fix Dialyzer errors
* Target Elixir 1.3+
* Update Jose and Phoenix dependencies
* Fixes for ttl and exp
* Added integration tests

# v 0.12.0
* Add `one_of` to permissions Plug to allow for OR'd sets of permissions as well as AND'd ones
* Fix infinite recursion bug when joining channels

# v 0.11.1

* Support for secret keys other than "oct" which provides support for signature
  algorithms other than HSxxx. See #122
* Fix incorrect param name in channel
* Tighten up log calls
* Fix moar typos
* General code cleanup
* Losen poison requirement to >= 1.3.0
* Use existing resource on conn if already present
* Fix refresh to correctly use revoke

# v 0.10.1

* Fix error in Guardian.Plug.ErrorHandler when Accept header is unset.
* Adding Guardian.Plug.EnsureNotAuthenticated to validates that user isn't logged
* Fix bug where TTL was not able to be set when generating tokens

# v 0.10.0

* Add a Guardian.Phoenix.Socket module and refactor Guardian.Channel
* Update JOSE to Version 1.6.0. Version 1.6.0 of erlang-jose
adds the ability of using libsodium and SHA-3 (keccack) algorithms.
This improves speed a lot.
* Adds travis
* Adds ability to use custom secrets
* Allows peeking at the contents of the token

# v 0.9.1

* Stop compiling permissions. This leads to weird bugs when permissions are
  changed but not recompiled

# v 0.9.0

* Remove internal calls to Dict
* Store the type of the token in the typ field rather than the aud field
  The aud field should default to the sub or failing that, the iss.
  This is to facilitate implementing an OAuth provider or just allowing
  folks to declare their own audience.

# v 0.8.1

* Fix a bug with logout where it was not checking the session, only the assigns
  This meant that if you had not verified the session the token would not be
  revoked.

# v 0.7.1

* Adds basic Phoenix controller helpers

# v 0.7.0

* Remove Joken from the dependencies and use JOSE instead.
* Add a refresh! function

# v 0.6.2

* Adds Guardian.Plug.authenticated?
* Adds simple claim checks to EnsureAuthenticated

### Bugs

* Fix an issue with permissions strings vs atoms (not encoding correctly)

# v 0.6.0
Rename

    Guardian.mint -> Guardian.encode_and_sign
    Guardian.verify -> Guardian.decode_and_verify

    Guardian.Plug.EnsureSession -> Guardian.Plug.EnsureAuthenticated
    Guardian.Plug.VerifyAuthorization -> Guardian.Plug.VerifyHeader

# v 0.5.2

Add new hooks on\_verify and on\_revoke
Remove multiple hooks registration

# v 0.5.1

Allow multiple hooks to be registered to Guardian

# v 0.5.0

Use strings for keys in the token.

# v 0.4.0

Remove CSRF tokens support. CSRF tokens are masked and so cannot be adequately
implemented.

# v 0.3.0

* Add callback hooks for authentication things

# v 0.2.0

* Update to use new Joken
* Include permissions

# v 0.0.1

Initial Release
