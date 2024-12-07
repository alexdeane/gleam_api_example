import app/clients/clamav/clam_scan_data.{type ClamScanData, Clean}
import gleam/bit_array
import gleam/erlang/os
import mug
import wisp

pub type ClientOptions {
  ClientOptions(
    ip_address: String,
    port: Int,
    max_stream_size: Int,
    max_chunk_size: Int,
    timeout: Int,
  )
}

pub fn scan_file(
  options: ClientOptions,
  bytes: BitArray,
) -> Result(ClamScanData, String) {
  todo
}

const end = "\u{0000}"

fn execute_clam_command(
  options: ClientOptions,
  command: String,
  bytes: BitArray,
  callback: fn(stream) -> Nil,
) -> Result(ClamScanData, mug.Error) {
  // TODO - connection pooling
  let socket_result =
    mug.new(options.ip_address, port: options.port)
    |> mug.timeout(milliseconds: options.timeout)
    |> mug.connect()

  case socket_result {
    Ok(socket) -> {
      let command_bytes =
        { "z" <> command <> end }
        |> bit_array.from_string

      use <- send_bytes(socket, command_bytes)

      callback(a)

      Ok(Clean)
    }
    Error(error) -> {
      wisp.log_error("Connection failed")
      Error(error)
    }
  }
}

fn send_bytes(
  socket,
  bytes: BitArray,
  callback: fn() -> Result(ClamScanData, mug.Error),
) -> Result(ClamScanData, mug.Error) {
  case mug.send(socket, bytes) {
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
  socket,
  timeout_milliseconds: Int,
  callback: fn(B) -> Result(ClamScanData, mug.Error),
) -> Result(ClamScanData, mug.Error) {
  case mug.receive(socket, timeout_milliseconds) {
    Ok(bytes) -> {
      let read = bytes.t
      callback(bytes)
    }
    Error(error) -> {
      wisp.log_error("Failed to receive byte packet")
      Error(error)
    }
  }
}
