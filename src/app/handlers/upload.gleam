import app/clients/clamav/client as clamav
import app/clients/clamav/client_options
import app/clients/clamav/results.{Clean, VirusDetected}
import app/common/response_factory
import gleam/http
import gleam/json
import gleam/list
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
        client_options.ClientOptions(
          host: clam_hostname,
          port: clam_port,
          max_chunk_size: 131_072,
          connection_timeout: 99_999_999,
          reply_timeout: 10_000,
        )

      case simplifile.read_bits(file.path) {
        Ok(file_bits) -> {
          case clamav.instream(options, file_bits) {
            Ok(Clean) -> response_factory.create(200, [#("result", "Clean")])
            Ok(VirusDetected(infected_files)) -> {
              let files =
                infected_files
                |> list.map(fn(infected_file) {
                  [
                    #("fileName", json.string(infected_file.file_name)),
                    #("virusName", json.string(infected_file.virus_name)),
                  ]
                })

              let body =
                json.object([
                  #("result", json.string("VirusDetected")),
                  #("infectedFiles", json.array(from: files, of: json.object)),
                ])
                |> json.to_string_builder()

              wisp.json_response(body, 200)
            }
            // TODO: more error info
            _ -> response_factory.create(502, [#("result", "ScanError")])
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
