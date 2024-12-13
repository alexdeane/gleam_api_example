import app/clients/clamav/client_options.{type ClientOptions}
import app/clients/clamav/common/tcp
import gleam/bit_array
import mug

const command_end = <<0:little-size(8)>>

pub fn execute_command(
  options: ClientOptions,
  command: String,
  callback: fn(mug.Socket) -> Result(a, mug.Error),
) -> Result(a, mug.Error) {
  // TODO - research connection pooling (may not be necessary)
  use socket <- tcp.connect(options)

  // Create the full command and convert it to bytes
  let command_bytes =
    { "z" <> command }
    |> bit_array.from_string
    |> bit_array.append(command_end)

  // Issue the command
  use <- tcp.send_bytes(socket, command_bytes)

  // Perform any subsequent operations on the socket
  callback(socket)
}
