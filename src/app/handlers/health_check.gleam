import app/clients/clamav/client as clam
import app/clients/clamav/client_options.{type ClientOptions}
import app/clients/clamav/results.{ConnectionError}
import app/common/response_factory
import birl
import gleam/int
import gleam/string
import gleam/string_tree
import wisp.{type Response}

pub fn handle(options: ClientOptions) -> Response {
  let start_ms = now_ms()

  case clam.ping(options) {
    Ok(Nil) -> {
      let elapsed = now_ms() - start_ms
      response_factory.create(200, [
        #("message", "clamav replied in " <> elapsed |> int.to_string <> "ms"),
      ])
    }
    Error(ConnectionError(e)) ->
      response_factory.create(502, [#("error", e |> string.inspect)])
    Error(error) ->
      wisp.json_response(
        error |> string.inspect |> string_tree.from_string,
        502,
      )
  }
}

fn now_ms() -> Int {
  birl.now() |> birl.to_unix_milli
}
