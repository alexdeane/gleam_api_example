# app

## Running the app

Standard
```sh
gleam build # Compile project
gleam run   # Run app
gleam test  # Run tests
```

Standard (script file)
```sh
gleam build # Compile project
gleam run -m gleescript # Produces a BEAM script file output
escript ./app # Run app
```

Docker
```sh
docker-compose up
```
