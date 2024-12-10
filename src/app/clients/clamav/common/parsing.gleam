import app/clients/clamav/results.{
  type ClamError, type ClamScanResult, CannotParseResponse, Clean, InfectedFile,
  ScanError, VirusDetected,
}
import gleam/list
import gleam/string
import wisp

pub fn parse_scan_result(
  response: String,
  callback: fn(ClamScanResult) -> Result(ClamScanResult, ClamError),
) -> Result(ClamScanResult, ClamError) {
  let formatted =
    response
    |> string.replace("\u{0000}", "")

  let formatted_lower =
    formatted
    |> string.lowercase()

  case formatted_lower |> string.ends_with("ok") {
    True -> callback(Clean)
    False -> {
      case formatted_lower |> string.ends_with("error") {
        True -> Error(ScanError(formatted))
        False -> {
          case formatted_lower |> string.ends_with("found") {
            True -> {
              use virus_detected <- parse_virus_detected(formatted)
              callback(virus_detected)
            }
            False -> {
              wisp.log_error("Could not parse response")
              Error(CannotParseResponse(formatted))
            }
          }
        }
      }
    }
  }
}

fn parse_virus_detected(
  response: String,
  callback,
) -> Result(ClamScanResult, ClamError) {
  let files =
    response
    |> string.split("FOUND")
    |> list.filter(fn(x) { x |> string.trim() != "" })
    |> list.map(fn(file_result) {
      let file_parts = file_result |> string.split(":")
      case file_parts {
        [file_name, virus_name] -> {
          InfectedFile(
            file_name: file_name |> string.trim(),
            virus_name: virus_name |> string.trim(),
          )
        }
        _ -> {
          wisp.log_error("Could not parse file result")
          InfectedFile(file_name: "UNKNOWN", virus_name: "UNKNOWN")
        }
      }
    })

  callback(VirusDetected(files))
}
