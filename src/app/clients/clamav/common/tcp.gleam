import app/clients/clamav/client_options.{type ClientOptions}
import gleam/bit_array
import gleam/string
import mug
import wisp

pub fn connect(
  options: ClientOptions,
  callback: fn(mug.Socket) -> Result(a, mug.Error),
) -> Result(a, mug.Error) {
  let socket =
    mug.new(options.host, options.port)
    |> mug.timeout(milliseconds: options.connection_timeout)
    |> mug.connect()

  case socket {
    Ok(socket) -> callback(socket)
    Error(error) -> {
      wisp.log_error(
        "Failed to connect to ClamAV server: " <> error |> string.inspect,
      )
      Error(error)
    }
  }
}

pub fn send_bytes(
  socket,
  bits: BitArray,
  callback: fn() -> Result(a, mug.Error),
) -> Result(a, mug.Error) {
  case mug.send(socket, bits) {
    Ok(_) -> callback()
    Error(error) -> {
      wisp.log_error("Failed to send byte packet: " <> error |> string.inspect)
      Error(error)
    }
  }
}

pub fn receive_bytes(
  socket: mug.Socket,
  timeout_milliseconds: Int,
  callback: fn(BitArray) -> Result(a, mug.Error),
) -> Result(a, mug.Error) {
  case mug.receive(socket, timeout_milliseconds) {
    Ok(bits) -> {
      let byte_size = bit_array.byte_size(bits)

      // Chop off the response end byte
      case bits |> bit_array.slice(0, byte_size - 1) {
        Ok(sliced_bits) -> sliced_bits |> callback
        Error(Nil) -> Error(mug.Einval)
      }
    }
    Error(error) -> {
      wisp.log_error(
        "Failed to receive byte packet: " <> error |> string.inspect,
      )
      Error(error)
    }
  }
}
