import app/clients/clamav/client_options.{type ClientOptions}
import app/clients/clamav/common/clam
import app/clients/clamav/common/parsing
import app/clients/clamav/common/tcp
import app/clients/clamav/results.{
  type ClamError, type ClamScanResult, CannotParseResponse, ConnectionError,
}
import gleam/bit_array
import gleam/int
import gleam/string
import mug
import wisp

const file_end = <<0:little-size(32)>>

pub fn instream(
  options: ClientOptions,
  file_content: BitArray,
) -> Result(ClamScanResult, ClamError) {
  // Pad the file contents to the nearest byte to be safe
  let padded_file_content = bit_array.pad_to_bytes(file_content)

  // Perform the scan
  case tcp_instream(options, padded_file_content) {
    Ok(response) -> {
      case bit_array.to_string(response) {
        Ok(response_text) -> {
          // Convert to string and parse
          use scan_result <- parsing.parse_scan_result(response_text)
          Ok(scan_result)
        }
        Error(_) -> {
          wisp.log_error("Could not parse response from ClamAV")
          Error(CannotParseResponse("Failed to parse response"))
        }
      }
    }
    Error(error) -> {
      wisp.log_error(
        "Failed to connect to ClamAV server: " <> error |> string.inspect,
      )
      Error(ConnectionError(error))
    }
  }
}

fn tcp_instream(
  options: ClientOptions,
  file_content: BitArray,
) -> Result(BitArray, mug.Error) {
  // Initialize socket with a command
  use socket <- clam.execute_command(options, "INSTREAM")

  wisp.log_info(":: Socket acquired")

  // Send the file contents
  use <- send_file(socket, file_content)

  wisp.log_info(":: File upload complete")

  // Receive the response
  use response_bytes <- tcp.receive_bytes(socket, options.reply_timeout)

  wisp.log_info(":: Received response")

  Ok(response_bytes)
}

fn send_file(
  socket: mug.Socket,
  file_contents: BitArray,
  callback: fn() -> Result(a, mug.Error),
) -> Result(a, mug.Error) {
  let byte_size = bit_array.byte_size(file_contents)

  let packet =
    byte_size
    |> get_length_indicator()
    |> bit_array.append(file_contents)
    |> bit_array.append(file_end)

  wisp.log_info(
    ":: Uploading file of size "
    <> byte_size |> int.to_string()
    <> "B. (Total packet size "
    <> packet |> bit_array.byte_size() |> int.to_string()
    <> "B)",
  )

  use <- tcp.send_bytes(socket, packet)

  callback()
}

fn get_length_indicator(length: Int) -> BitArray {
  // Length indicator shall be 4 bytes in network byte order (Big Endian)
  <<length:big-size(32)>>
}
