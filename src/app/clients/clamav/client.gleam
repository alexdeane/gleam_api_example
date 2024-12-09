import app/clients/clamav/clam_scan_data.{
  type ClamScanData, Clean, VirusDetected,
}
import gleam/bit_array
import gleam/int
import gleam/io
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
  file_contents: BitArray,
) -> Result(ClamScanData, mug.Error) {
  // Pad the file contents to the nearest byte
  // This may not be necessary idk yet
  let padded_file_contents = bit_array.pad_to_bytes(file_contents)

  // Initialize socket with a command
  use socket <- execute_clam_command(options, "INSTREAM")

  wisp.log_info(":: Socket acquired")

  // Send the file contents
  use <- send_file(socket, padded_file_contents)

  wisp.log_info(":: File upload complete")

  // Receive the response
  use response_bytes <- receive_bytes(socket, options.reply_timeout)

  wisp.log_info(":: Received response")

  case bit_array.to_string(response_bytes) {
    Ok(response_text) -> {
      // TODO: Parse the response from the resulting bytes
      Ok(VirusDetected("virus", response_text))
    }
    Error(_) -> {
      // TODO - this error doesn't make sense - need to create
      // our own error model
      Error(mug.Econnaborted)
    }
  }
}

const command_end = <<0:little-size(8)>>

const file_end = <<0:little-size(32)>>

fn execute_clam_command(
  options: ClientOptions,
  command: String,
  callback: fn(mug.Socket) -> Result(ClamScanData, mug.Error),
) -> Result(ClamScanData, mug.Error) {
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
      io.debug(error)
      wisp.log_error("Connection failed")
      Error(error)
    }
  }
}

fn send_bytes(
  socket,
  bits: BitArray,
  callback: fn() -> Result(result, mug.Error),
) -> Result(result, mug.Error) {
  case mug.send(socket, bits) {
    Ok(_) -> {
      callback()
    }
    Error(error) -> {
      wisp.log_error("Failed to send byte packet")
      Error(error)
    }
  }
}

fn receive_bytes(
  socket: mug.Socket,
  timeout_milliseconds: Int,
  callback: fn(BitArray) -> Result(ClamScanData, mug.Error),
) -> Result(ClamScanData, mug.Error) {
  case mug.receive(socket, timeout_milliseconds) {
    Ok(bits) -> {
      callback(bits)
    }
    Error(error) -> {
      io.debug(error)
      wisp.log_error("Failed to receive byte packet")
      Error(error)
    }
  }
}

fn send_file(
  socket: mug.Socket,
  file_contents: BitArray,
  callback: fn() -> Result(ClamScanData, mug.Error),
) -> Result(ClamScanData, mug.Error) {
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
