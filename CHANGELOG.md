# v 0.6.2

* Adds Guardian.Plug.authenticated?

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
