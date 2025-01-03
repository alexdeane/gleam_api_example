import app/router
import gleam/erlang/process
import glenvy/env
import mist
import wisp
import wisp/wisp_mist

pub fn main() {
  // This sets the logger to print INFO level logs, and other sensible defaults
  // for a web application.
  wisp.configure_logger()

  // Here we generate a secret key, but in a real application you would want to
  // load this from somewhere so that it is not regenerated on every restart.
  let secret_key_base = wisp.random_string(64)

  let host = case env.get_string("HOST") {
    Ok(host) -> host
    Error(_) -> "localhost"
  }

  // Start the Mist web server.
  let assert Ok(_) =
    wisp_mist.handler(router.route_request, secret_key_base)
    |> mist.new
    |> mist.bind(host)
    // Binding to 0.0.0.0 lets it work in the container - for local change this to `localhost`. TODO: Pull from config
    |> mist.port(8000)
    |> mist.start_http

  // The web server runs in new Erlang process, so put this one to sleep while
  // it works concurrently.
  process.sleep_forever()
}
