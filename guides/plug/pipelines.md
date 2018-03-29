# Pipelines

Guardians Plug support provides an easy and composable way to put together your authentication.

Different parts of your application are going to need different parts of the authentication system. Some areas a user can be logged in, or not. Others users are required.

Guardians composable nature, coupled with the composable nature of Plug means that the options are pretty much endless. For that reason this documentation will focus on walking through how Guardian pipelines work so you can get just the right solution for you.

## What is a Guardian Pipeline?

A pipeline provides two main pieces.

1. Access to your [implementation module](introduction-implementation.html)
2. An error handler for when folks aren't authenticated

The pipeline puts these two modules into the `Plug.Conn` struct so that they're available to all downstream plugs. This means that we can set these at the start of our plug chain and even swap them out downstream if we need to. More on that later though.

## A manual version

When we `use Guardian.Plug.Pipeline` it's just wrapping up a bunch of plugs for us into a nice neat bundle. In order to understand what it's doing we'll first look at it manually.

The first step is to use the pipeline plug to specify the implementation module and error handler.

```elixir
plug Guardian.Plug.Pipeline, module: AuthMe.UserManager.Guardian,
                             error_handler: AuthMe.UserManager.ErrorHandlers.JSON
```

This injects the module and error handler into the `conn` struct and makes them available to downstream plugs.

The next thing that we're going to want to do is find the token. Guardian provides plugs to find and validate tokens from a number of sources.

* [VerifySession](Guardian.Plug.VerifySession.html) - For when the token is stored in the session
* [VerifyHeader](Guardian.Plug.VerifyHeader.html) - `Authorization` header token location
* [VerifyCookie](Guardian.Plug.VerifySession.html) - A cookie has the cookie stored

```elixir
# ...

# plug Guardian.Plug.Pipeline (from above)

# Look for a token in the session.
# If there is no session or no token nothing happens and control is passed to the next plug
# If a token is found it's verified and added to the conn struct available with `Guardian.Plug.current_token` and `Guardian.Plug.current_claims`
plug Guardian.Plug.VerifySession, %{"typ" => "access"}

# Look for a token in the HTTP Authorization header. (prefixed with `"Bearer "`)
plug Guardian.Plug.VerifyHeader, %{"typ" => "access"}
```

These two plugs will look for tokens in the given locations and also restrict them to only validate for tokens that have the claim `typ == "access"`. You don't need to restrict to a type or you could add other literal claims to verify.

So far in our manual pipeline we've not actually enforced someone is logged in or if they are, we haven't loaded the resource associated with the token. Lets add that next.

```elixir
# return unauthenticated via the error handler if there is no validated token found previously
plug Guardian.Plug.EnsureAuthenticated

# if there is a verified token, load the user using the implementation module
plug Guardian.Plug.LoadResource
```

That's effectively our entire pipeline. Putting it all together in a Phoenix router:

```elixir
pipeline :auth do
  plug Guardian.Plug.Pipeline, module: AuthMe.UserManager.Guardian,
                               error_handler: AuthMe.UserManager.ErrorHandlers.JSON

  plug Guardian.Plug.VerifySession, %{"typ" => "access"}
  plug Guardian.Plug.VerifyHeader, %{"typ" => "access"}
  plug Guardian.Plug.EnsureAuthenticated
  plug Guardian.Plug.LoadResource
end

scope "/", AuthMeWeb do
  pipe_through [:auth]
end
```

## Module version

You can take the above setup and wrap it up in a plug all of it's own.

```elixir
defmodule AuthMe.UserManager.Pipeline do
  use Guardian.Plug.Pipeline, otp_app: :auth_me,
                              module: AuthMe.UserManager.Guardian,
                              error_handler: AuthMe.UserManager.ErrorHandlers.JSON

  plug Guardian.Plug.VerifySession, %{"typ" => "access"}
  plug Guardian.Plug.VerifyHeader, %{"typ" => "access"}
  plug Guardian.Plug.EnsureAuthenticated
  plug Guardian.Plug.LoadResource
end
```

This is a plug that you can use anywhere you'd normally use a plug.

```elixir
# phoenix router

pipeline :auth do
  plug AuthMe.UserManager.Pipeline
end

scope "/", AuthMe do
  pipe_through [:auth]
end
```

## Changing the error handler

Sometimes we need to change out the error handler. For example maybe in one area there's a module that redirects for customers, one for admins, maybe there's one that renders a page and maybe one that does JSON responses. That's a lot of behaviour to try to wrap into a single pipeline module. It's for this reason that you can change your error handler (and even your module) anytime by using the `Guardian.Plug.Pipeline` plug. Just specify which error handler to use downstream and you're good to go. As an example using a Phoneix router:

```elixir
  pipeline :auth do
    plug AuthMe.UserManager.Pipeline
  end

  pipeline :auth_html_errors do
    plug Guardian.Plug.Pipeline, error_handler: AuthMe.UserManager.ErrorHandlers.HTML
  end

  pipeline :auth_json_errors do
    plug Guardian.Plug.Pipeline, error_handler: AuthMe.UserManager.ErrorHandlers.JSON
  end

  scope "/api" do
    pipe_through [:auth, :auth_json_errors]
    # ...
  end

  scope "/www" do
    pipe_through [:auth, :auth_html_errors]
    # ...
  end
```

We don't have to just handle these in the router though. In Phoenix we can also use the controller.

```elixir
defmodule AuthMeWeb.SnowflakeController do
  use AuthMeWeb, :controller

  plug Guardian.Plug.Pipeline, error_handler: __MODULE__

  # ...

  def auth_error(conn, {type, reason}, opts) do
    # handle with a redirect or render
  end
end
```

## Good practices

The plugs for Guardian are very composable, as is Plug itself and Phoenix routes.

It's a good idea to have at least two Phoneix pipelines for authentication.

1. Find and verify the token if it's provided
2. Ensure authenticated where appropriate

The `Guardian.Plug.VerifySession` will work fine if sessions are loaded and if they're no it will just move on to the next plug so we can always just check both.

In this example we'll show it without the Pipeline module. Using the pipeline module can tidy things up for you and make it reusable if you're not using Phoenix.

```elixir
pipeline :maybe_auth do
  plug Guardian.Plug.Pipeline, module: AuthMe.UserManager.Guardian,
                               error_handler: AuthMe.UserManager.ErrorHandlers.JSON
  plug Guardian.Plug.VerifySession, %{"typ" => "access"}
  plug Guardian.Plug.VerifyHeader, %{"typ" => "access"}
  # if there isn't anyone logged in we don't want to return an error. Use allow_blank
  plug Guardian.Plug.LoadResource, allow_blank: true
end

pipeline :ensure_auth do
  plug Guardian.Plug.EnsureAuthenticated
end
```

Using these two pipelines should give you plenty of mileage in your router. Remember that the pipeline applies downstream so you can change out the module or error handler anywhere downstream including your controllers.
