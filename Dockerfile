FROM adeane43/gleam AS build

# Build app
COPY ./gleam.toml /gleam.toml
COPY ./manifest.toml /manifest.toml

RUN gleam deps download

COPY ./src/ /src

RUN gleam build
RUN gleam run -m gleescript

### Uncomment for production
# ## Run app
# FROM debian:bullseye

# # Prevents apt-get from requiring user input
# ENV DEBIAN_FRONTEND=noninteractive 

# # Install erlang
# RUN apt-get update && apt-get install erlang -y

# # Copy the built script
# COPY --from=build ./app ./app

EXPOSE 8000

ENTRYPOINT ["escript", "./app"]