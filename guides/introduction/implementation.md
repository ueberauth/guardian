# Implementation modules

Implementation modules are the heart of how you interact with Guardian in your application.
Almost all functions for using Guardian are done via your implementation module.

They encapsulate the configuration and behaviour that you specify and utilize a [token](tokens-start.html) backend to implement the details of the type of token you've chosen (default JWT).

Previous versions of Guardian used the Guardian module directly which was very limiting.
This limitation forced only a single type of token could be used for your entire application and made customization difficult, verbose and somewhat confusing.

## Usage

Guardian is used to encode and decode tamper proof tokens for the purpose of authentication. For integrations see [the plug guide](plug-start.html) and/or [the Phoenix guide](phoenix-start.html). If you're using Plug or Phoenix you probably won't need to drop down to this level but from time to time it's useful.

### Basics

The main functions that are useful for encoding and decoding tokens are:

```elixir
# create tokens
{:ok, token, full_claims} = MyApp.TokenImpl.encode_and_sign(user)

# decoding tokens
{:ok, claims} = MyApp.TokenImpl.decode_and_verify(token_string)

# decoding token and fetching resource in one step
{:ok, user, claims} = MyApp.TokenImpl.resource_from_token(token_string)
```

When creating tokens, you can add custom claims to your tokens. The resulting token will be a merge (in order of application) of:

* the claims provided by your token
* the claims you pass in
* any changes you make in your `Guardian.build_claims` callback

For example:

```elixir
{:ok, token, full_claims = MyApp.TokenImpl.encode_and_sign(user, %{some: "data to store"})
```

## Basic Setup

The most basic setup for an implementation module consists of `use Guardian` passing the atom of your otp app. See [JWT implementation](tokens-jwt-setup.html) for specific information about setting up for JWT.

```elixir
defmodule MyApp.TokenImpl do
  use Guardian, otp_app: :my_app

  def subject_for_token(resource, options) do
    {:ok, resource.id}
  end

  def resource_from_claims(claims) do
    # find user from claims["sub"] or other information you stored inside claims
  end
end
```

This setup will use your configuration and the default options.
If you want to change your token backend, you can use the `token_module` in your [configuration](introduction-implementation.html#configuration).

The functions `subject_for_token` and `resource_from_claims` are the only two functions that must be implemented. They are effectively opposites of one another.

* `subject_for_token` - provide the identifier you will use in `resource_from_claims` to lookup the resource
* `resource_from_claims` - using the identifier provided by `subject_for_token` find the associated resource

All other [callbacks](introduction-implementation#callbacks) have a default implementation and are optional.

`subject_for_token` provides the `sub` field (in JWT parlance) which identifies the subject which is usually the resource to use. The subject field can be anything that helps you identify which resource is logged in. Some examples:

* `"User:420"`
* `"420"`
* `"u|420"`

Some thought about what this is can be useful. If you have more than one type of struct that you want to be able to authenticate prefixing with some type of struct identifier is helpful to switch (prefix can be pattern matched, suffix cannot). Once your token is out in the wild, you will need to support all of those subject schemes until the last issued token expires or is revoked. An example of pattern matching via a prefix:

```elixir
def subject_for_token(%User{uid: uid} = user, _claims) do
  {:ok, "User:#{uid}"}
end

def subject_for_token(_, _), do: {:error, :unhandled_resource_type}

def resource_from_claims(%{"sub" => "User:" <> uid}) do
  case Repo.get_by(User, %{uid: uid}) do
    nil -> {:error, :user_not_found}
    user -> {:ok, user}
  end
end

def resource_from_claims(_), do: {:error, :unhandled_resource_type}
```


## Configuration

## Callbacks

## Advanced Usage
