import app/common/response_factory
import gleam/http
import wisp

pub fn handle(req: wisp.Request) -> wisp.Response {
  // Assert that the request is a POST request
  use <- wisp.require_method(req, http.Post)

  // Parse the form data
  use form_data <- wisp.require_form(req)

  case form_data.files {
    [#(name, file), ..] -> {
      wisp.log_info("Received file " <> name)

      wisp.response(202)
    }
    _ -> {
      response_factory.bad_request("File is required")
    }
  }
}
