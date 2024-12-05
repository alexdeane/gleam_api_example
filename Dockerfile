FROM debian:bullseye AS build

# Prevents apt-get from requiring user input
ENV DEBIAN_FRONTEND=noninteractive 

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    wget \
    gnupg \
    sudo

# Add to /etc/apt/sources.list
RUN apt-get install software-properties-common -y
RUN add-apt-repository "deb http://binaries2.erlang-solutions.com/debian/ bullseye-esl-erlang-26 contrib" -y

# Add Erlang Solutions repo keys:
RUN wget https://binaries2.erlang-solutions.com/GPG-KEY-pmanager.asc
RUN sudo apt-key add GPG-KEY-pmanager.asc

# Update apt and install esl-erlang
RUN sudo apt update
RUN sudo apt install esl-erlang -y

ARG GLEAM_VERSION

# Download and install the precompiled Gleam binary for x86_64 Linux with musl libc
RUN curl -fsSL https://github.com/gleam-lang/gleam/releases/download/v${GLEAM_VERSION}/gleam-v${GLEAM_VERSION}-x86_64-unknown-linux-musl.tar.gz \
    | tar -xzC /usr/local/bin gleam

# Download and install Rebar3
RUN wget -O ./tmp/rebar3 https://s3.amazonaws.com/rebar3/rebar3 && \
    chmod +x ./tmp/rebar3

RUN ./tmp/rebar3 local install

# Add rebar3 to PATH
ENV PATH=$PATH:/root/.cache/rebar3/bin

COPY ./gleam.toml /gleam.toml
COPY ./manifest.toml /manifest.toml
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