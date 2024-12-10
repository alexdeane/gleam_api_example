import app/clients/clamav/client as clam
import app/clients/clamav/client_options.{type ClientOptions}
import app/clients/clamav/results.{ConnectionError}
import app/common/response_factory
import gleam/string
import wisp.{type Response}

pub fn handle(options: ClientOptions) -> Response {
  case clam.ping(options) {
    Ok(_) -> wisp.ok()
    Error(ConnectionError(e)) ->
      response_factory.create(502, [#("error", e |> string.inspect)])
    _ -> wisp.internal_server_error()
  }
}
