import app/clients/clamav/clam_scan_data.{Clean, VirusDetected}
import app/clients/clamav/client as clamav
import app/common/response_factory
import gleam/http
import gleam/io
import glenvy/env
import simplifile
import wisp

pub fn handle(req: wisp.Request) -> wisp.Response {
  // Assert that the request is a POST request
  use <- wisp.require_method(req, http.Post)

  // Parse the form data
  use form_data <- wisp.require_form(req)

  case form_data.files {
    [#(name, file), ..] -> {
      wisp.log_info("Received file " <> name)

      let assert Ok(clam_hostname) = env.get_string("CLAMAV_HOSTNAME")
      let assert Ok(clam_port) = env.get_int("CLAMAV_PORT")

      let options =
        clamav.ClientOptions(
          ip_address: clam_hostname,
          port: clam_port,
          max_chunk_size: 131_072,
          connection_timeout: 99_999_999,
          reply_timeout: 10_000,
        )

      case simplifile.read_bits(file.path) {
        Ok(file_bits) -> {
          let scan_result = clamav.scan_file(options, file_bits)

          case scan_result {
            Ok(Clean) -> {
              wisp.ok()
            }
            Ok(VirusDetected(_virus_name, response_text)) -> {
              response_factory.create(200, [#("message", response_text)])
            }
            Error(_) -> {
              wisp.internal_server_error()
            }
          }
        }
        Error(_) -> {
          wisp.internal_server_error()
        }
      }
    }
    _ -> {
      response_factory.bad_request("File is required")
    }
  }
}
