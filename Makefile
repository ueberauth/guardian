deps:
	mix local.hex --force
	mix local.rebar --force
	mix deps.get

testing: deps
	mix do compile --warnings-as-errors --force
	mix format --check-formatted
	mix credo --strict
	MIX_ENV=test mix coveralls.json
	mix dialyzer --halt-exit-status

docs:
	mix inch.report
