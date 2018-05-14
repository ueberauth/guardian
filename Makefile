deps:
	mix local.hex --force
	mix local.rebar --force
	mix deps.get

testing: deps
	mix credo
	mix format --check-formatted
	MIX_ENV=test mix coveralls.json

docs:
	mix inch.report
