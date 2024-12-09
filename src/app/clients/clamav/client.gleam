import app/clients/clamav/clam_scan_data.{
  type ClamError, type ClamScanData, CannotParseResponse, Clean, ConnectionError,
  InfectedFile, ScanError, VirusDetected,
}
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string
import mug
import wisp

pub type ClientOptions {
  ClientOptions(
    ip_address: String,
    port: Int,
    max_chunk_size: Int,
    connection_timeout: Int,
    reply_timeout: Int,
  )
}

pub fn scan_file(
  options: ClientOptions,
  file_content: BitArray,
) -> Result(ClamScanData, ClamError) {
  // Pad the file contents to the nearest byte to be safe
  let padded_file_content = bit_array.pad_to_bytes(file_content)

  // Perform the scan
  case instream(options, padded_file_content) {
    Ok(response) -> {
      case bit_array.to_string(response) {
        Ok(response_text) -> {
          // Convert to string and parse
          use scan_data <- parse_scan_data(response_text)
          Ok(scan_data)
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

const command_end = <<0:little-size(8)>>

const file_end = <<0:little-size(32)>>

fn instream(options: ClientOptions, file_content: BitArray) {
  // Initialize socket with a command
  use socket <- execute_clam_command(options, "INSTREAM")

  wisp.log_info(":: Socket acquired")

  // Send the file contents
  use <- send_file(socket, file_content)

  wisp.log_info(":: File upload complete")

  // Receive the response
  use response_bytes <- receive_bytes(socket, options.reply_timeout)

  wisp.log_info(":: Received response")

  Ok(response_bytes)
}

fn execute_clam_command(
  options: ClientOptions,
  command: String,
  callback: fn(mug.Socket) -> Result(a, mug.Error),
) -> Result(a, mug.Error) {
  // TODO - connection pooling
  let socket_result =
    mug.new(options.ip_address, port: options.port)
    |> mug.timeout(milliseconds: options.connection_timeout)
    |> mug.connect()

  case socket_result {
    Ok(socket) -> {
      // Create the full command and convert it to bytes
      let command_bytes =
        { "z" <> command }
        |> bit_array.from_string
        |> bit_array.append(command_end)

      // Issue the command
      use <- send_bytes(socket, command_bytes)

      // Perform any subsequent operations on the socket
      callback(socket)
    }
    Error(error) -> {
      wisp.log_error("Failed to acquire socket")
      Error(error)
    }
  }
}

fn send_bytes(
  socket,
  bits: BitArray,
  callback: fn() -> Result(a, mug.Error),
) -> Result(a, mug.Error) {
  case mug.send(socket, bits) {
    Ok(_) -> {
      callback()
    }
    Error(error) -> {
      wisp.log_error("Failed to send byte packet: " <> error |> string.inspect)
      Error(error)
    }
  }
}

fn receive_bytes(
  socket: mug.Socket,
  timeout_milliseconds: Int,
  callback: fn(BitArray) -> Result(a, mug.Error),
) -> Result(a, mug.Error) {
  case mug.receive(socket, timeout_milliseconds) {
    Ok(bits) -> {
      callback(bits)
    }
    Error(error) -> {
      wisp.log_error(
        "Failed to receive byte packet: " <> error |> string.inspect,
      )
      Error(error)
    }
  }
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

  use <- send_bytes(socket, packet)

  callback()
}

fn get_length_indicator(length: Int) -> BitArray {
  // Length indicator shall be 4 bytes in network byte order (Big Endian)
  <<length:big-size(32)>>
}

fn parse_scan_data(
  response: String,
  callback: fn(ClamScanData) -> Result(ClamScanData, ClamError),
) -> Result(ClamScanData, ClamError) {
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
) -> Result(ClamScanData, ClamError) {
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
