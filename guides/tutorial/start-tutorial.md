# Getting started with Guardian

Getting started with Guardian is easy. This tutorial will cover

* Setting up the basics of Guardian
* HTTP integration
* Login/Logout

We'll use Phoenix for this tutorial since most folks will be using it. There is no requirement to use Phoenix with Guardian but it makes this tutorial easier.

This tutorial was based on [this article](https://medium.com/@tylerpachal/session-authentication-example-for-phoenix-1-3-using-guardian-1-0-beta-a228c78478e6) by [Tyler Pachal](https://github.com/TylerPachal).

We'll also use the default token type of JWT. Again with this you don't _have_ to use JWT for your token backend. See the [token documentation](tokens-start.html) for more information.

Authentication consists of a challenge phase (prove who you are) and then followed by a verification phase (has this actor proven who they are?). Guardian looks after the second part for you. It's up to your application to implement the challenge phase after which Guardian will do the rest. In this tutorial we'll use [comeonin](https://github.com/riverrun/comeonin) with [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) for the challenge phase.

Lets generate an application.

```sh
$ mix phx.new auth_me
```

## Specify your dependencies

You'll need to update the dependencies to whatever is latest.

```elixir
## mix.exs

defp deps do
  [
    {:guardian, "~> 1.0"},
    {:comeonin, "~> 4.0"},
    {:bcrypt_elixir, "~> 0.12"},
  ]
end
```

## Create a user manager

We'll need something to authenticate. How Users are created and what they can do is outside the scope of this tutorial. If you already have a user model you can skip this part.

```sh
$ mix phx.gen.context UserManager User users username:string password:string
```

## Create implementation module

Guardian needs an implementation. This implementation module encapsulates:

* Token type
* Configuration
* Encoding/Decoding
* Callbacks

For more information please reference the [implementation module docs](introduction-implementation.html).

You can have as many implementation modules as you need to depending on your application. For this one though we only have a simple user system so we'll only need one.

```elixir
## lib/auth_me/user_manager/guardian.ex

defmodule AuthMe.UserManager.Guardian do
  use Guardian, otp_app: :auth_me

  alias AuthMe.UserManager

  def subject_for_token(user, _claims) do
    {:ok, to_string(user.id)}
  end

  def resource_from_claims(%{"sub" => id}) do
    case UserManager.get_user!(id) do
      nil -> {:error, :resource_not_found}
      user -> {:ok, user}
    end
  end
end
```

`subject_for_token` and `resource_from_claims` are inverses of one another. `subject_for_token` is used to encode the resource into the token, and `resource_from_claims` is used to rehydrate the resource from the claims.

There are many other [callbacks](Guardian.html#callbacks) that you can use, but we're going basic.

## Setup Guardian config

To use the JWT token type, we'll need a secret. We'll use the `HS512` algorithm which is a simple hashing algorithm. The most basic configuration is very straight forward.

The secret can be any string but it's recommended that you use the generator provided with Guardian for this.

```sh
$ mix guardian.gen.secret
```

Copy the output from the previous command and add it to your configuration.

```elixir
## config.exs

config :auth_me, AuthMe.UserManager.Guardian,
  issuer: "auth_me",
  secret_key: "" # put the result of the mix command above here
```

You should change the secret key for each environment and manage them with your secret management strategy.

## Password hashing

This too is not strictly required for Guardian. If you already have a way for you to verify user/password for your user model you can skip this part.

We'll implement a simple version of password hashing for this tutorial. This is up to your application and is only shown here for example purposes.

We added `:comeonin` and `:bcrypt_elixir` to our mix deps at the start. We're going to use them in two places.

1. When setting the password for the user
2. When verifying the login credentials

```elixir
## lib/auth_me/user_manager/user.ex

alias Comeonin.Bcrypt

def changeset(%User{} = user, attrs) do
  user
  |> cast(attrs, [:username, :password])
  |> validate_required([:username, :password])
  |> put_password_hash()
end

defp put_password_hash(%Ecto.Changeset{valid?: true, changes: %{password: password}} = changeset) do
  change(changeset, password: Bcrypt.hashpwsalt(password))
end

defp put_password_hash(changeset), do: changeset
```

Now we need a way to verify the username/password credentials.

```elixir
## lib/auth_me/user_manager/user_manager.ex

alias Comeonin.Bcrypt

def authenticate_user(username, plain_text_password) do
  query = from u in User, where: u.username == ^username
  case Repo.one(query) do
    nil ->
      Bcrypt.dummy_checkpw()
      {:error, :invalid_credentials}
    user ->
      if Bcrypt.checkpw(plain_text_password, user.password) do
        {:ok, user}
      else
        {:error, :invalid_credentials}
      end
  end
end
```

That's it for Guardian setup. We had some User setup in there too that was unrelated but if you don't have a user model it will help you get started.

The next step is getting it into your application via HTTP.

## Pipelines

For HTTP Guardian makes use of the Plug architecture and uses it to construct pipelines. The pipeline provides downstream plugs with the implementation module and the error handler that the Guardian plugs require to do their job.

Please read the [pipeline guide](plug-pipeline.html) for more information.

We want our pipeline to look after session and header authentication (where to look for the token), load the resource but not enforce it. By not enforcing it we can have a "logged in" or "maybe logged in". We can use the [Guardian.Plug.EnsureAuthenticated](Guardian.Plug.EnsureAuthenticated.html) plug for those cases where we must have a logged in resource by using Phoenix pipelines in the router.

```elixir
## lib/auth_me/user_manager/pipeline.ex

defmodule AuthMe.UserManager.Pipeline do
  use Guardian.Plug.Pipeline,
    otp_app: :auth_me,
    error_handler: AuthMe.UserManager.ErrorHandler,
    module: AuthMe.UserManager.Guardian

  # If there is a session token, restrict it to an access token and validate it
  plug Guardian.Plug.VerifySession, claims: %{"typ" => "access"}
  # If there is an authorization header, restrict it to an access token and validate it
  plug Guardian.Plug.VerifyHeader, claims: %{"typ" => "access"}
  # Load the user if either of the verifications worked
  plug Guardian.Plug.LoadResource, allow_blank: true
end
```

We'll also need the error handler referenced in our pipeline to handle the case where there was a failure to authenticate.

```elixir
## lib/auth_me/user_manager/error_handler.ex

defmodule AuthMe.UserManager.ErrorHandler do
  import Plug.Conn

  def auth_error(conn, {type, _reason}, _opts) do
    body = to_string(type)
    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(401, body)
  end
end
```

## Controller

This pipeline is now ready for us to use. Now we need some way to login/logout the user and some resource to protect. For this we'll create a sessions controller, and use the PageController for our protected resource

```elixir
## lib/auth_me_web/controllers/session_controller.ex

defmodule AuthMeWeb.SessionController do
  use AuthMeWeb, :controller

  alias AuthMe.{UserManager, UserManager.User, UserManager.Guardian}

  def new(conn, _) do
    changeset = UserManager.change_user(%User{})
    maybe_user = Guardian.Plug.current_resource(conn)
    if maybe_user do
      redirect(conn, to: "/secret")
    else
      render(conn, "new.html", changeset: changeset, action: session_path(conn, :login))
    end
  end


  def login(conn, %{"user" => %{"username" => username, "password" => password}}) do
    UserManager.authenticate_user(username, password)
    |> login_reply(conn)
  end

  def logout(conn, _) do
    conn
    |> Guardian.Plug.sign_out()
    |> redirect(to: "/login")
  end

  defp login_reply({:ok, user}, conn) do
    conn
    |> put_flash(:success, "Welcome back!")
    |> Guardian.Plug.sign_in(user)
    |> redirect(to: "/secret")
  end

  defp login_reply({:error, reason}, conn) do
    conn
    |> put_flash(:error, to_string(reason))
    |> new(%{})
  end
end
```

Create a session view

```elixir
## lib/auth_me_web/views/session_view.eex

defmodule AuthMeWeb.SessionView do
  use AuthMeWeb, :view
end
```

And for the login template and secret template:

```
## lib/auth_ex_web/templates/session/new.html.eex

<h2>Login Page</h2>

<%= form_for @changeset, @action, fn f -> %>

  <div class="form-group">
    <%= label f, :username, class: "control-label" %>
    <%= text_input f, :username, class: "form-control" %>
    <%= error_tag f, :username %>
  </div>

  <div class="form-group">
    <%= label f, :password, class: "control-label" %>
    <%= password_input f, :password, class: "form-control" %>
    <%= error_tag f, :password %>
  </div>

  <div class="form-group">
    <%= submit "Submit", class: "btn btn-primary" %>
  </div>
<% end %>
```

Lets make the secret implementation.

```elixir
## lib/auth_me_web/controllers/page_controller.ex

defmodule AuthMeWeb.PageController do
  use AuthMeWeb, :controller

  def secret(conn, _) do
    user = Guardian.Plug.current_resource(conn)
    render(conn, "secret.html", current_user: user)
  end
end
```

We use the `Guardian.Plug.current_resource(conn)` function here to fetch the resource. You must load this first using the `Guardian.Plug.LoadResource` plug which we included in our auth pipeline earlier.

```
## lib/auth_me_web/templates/page/secret.html.eex
<h2>Secret Page</h2>
<p>You can only see this page if you are logged in</p>
<p>You're logged in as <%= @current_user.username %></p>
```

## Routes

Ok. So the controller and views are not strictly part of Guardian but we need some way to interact with it. From here the only thing left for us to do is to wire up our router.

```elixir
# Our pipeline implements "maybe" authenticated. We'll use the `:ensure_auth` below for when we need to make sure someone is logged in.
pipeline :auth do
  plug AuthMe.UserManager.Pipeline
end

# We use ensure_auth to fail if there is no one logged in
pipeline :ensure_auth do
  plug Guardian.Plug.EnsureAuthenticated
end

# Maybe logged in routes
scope "/", AuthMeWeb do
  pipe_through [:browser, :auth]

  get "/", PageController, :index

  get "/login", SessionController, :new
  post "/login", SessionController, :login
  post "/logout", SessionController, :logout
end

# Definitely logged in scope
scope "/", AuthMeWeb do
  pipe_through [:browser, :auth, :ensure_auth]

  get "/secret", PageController, :secret
end
```

There's a little bit happening here.

1. We created a Phoenix pipeline that just delegates to our Guardian pipeline to login someone if we find a token in the session or header. This does not restrict access.
2. We restrict access using both our `:auth` and `:ensure_auth` phoenix pipelines and use that to protect our "secret" route.

Note that you must use the `:auth` pipeline before the `:ensure_auth` one to make sure that we have fetched and verified the token. We're also loading the resource but that is not required for ensure auth.

## Try it out

Migrate your users table.

```sh
mix ecto.migrate
```

Since we didn't implement a form for creating a user we'll need to do that from the command line. Open up iex

```sh
iex -S mix
```

Create the user:

```sh
AuthMe.UserManager.create_user(%{username: "me", password: "secret"})
```

Now exit and start up your server:

```sh
mix phx.server
```

Open up `localhost:4000/login` and you should be able to login with your `me` `secret` credentials!
