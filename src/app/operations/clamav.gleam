import gleam/erlang/os
import gleam/os
import mug

pub type ClientOptions {
  ClientOptions(
    ip_address: String,
    port: Int,
    max_stream_size: Int,
    max_chunk_size: Int,
    timeout: Int,
  )
}

pub type ClamScanResult {
  ClamScanResult(
    virus_detected: Bool,

  )
}

pub type ClamError {
  ConnectionFailed
  Timeout
}

pub fn scan_file(
  options: ClientOptions,
  bytes: BitArray,
) -> Result(VirusResult, String) {
  todo
}

fn execute_clam_command(
  options: ClientOptions,
  command_name: String,
  bytes: BitArray,
  callback: fn(Stream) -> Nil,
) -> Option(ClamError) {
  let socketResult = mug.new(options.ip_address, port: options.port)
    |> mug.timeout(milliseconds: options.timeout)
    |> mug.connect()

  case socketResult {
    Ok(socket) -> {
      mug.send(socket, )
    }
    Error(error) -> {

    }
  }
}
