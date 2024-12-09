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
    max_stream_size: Int,
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

  wisp.log_info(":: socket acquired")

  // Send the file contents
  use <- chunk_and_send_file(options, socket, padded_file_contents)

  wisp.log_info(":: sent file")

  // Receive the response
  use response_bytes <- receive_bytes(socket, options.reply_timeout)

  wisp.log_info(":: received response")

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

const end = "\u{0000}"

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
      // Create the full ommand and convert it to bytes
      let command_bytes =
        { "z" <> command <> end }
        |> bit_array.from_string

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
      wisp.log_error("Failed to receive byte packet")
      Error(error)
    }
  }
}

fn chunk_and_send_file(
  options: ClientOptions,
  socket: mug.Socket,
  file_contents: BitArray,
  callback: fn() -> Result(ClamScanData, mug.Error),
) -> Result(ClamScanData, mug.Error) {
  let file_bits = bit_array.bit_size(file_contents)

  wisp.log_info(
    ":: Uploading file of size " <> int.to_string(file_bits) <> " bits",
  )

  let send_result =
    recursive_chunk_and_send(options, socket, file_contents, file_bits, 0)

  case send_result {
    Ok(_) -> {
      callback()
    }
    Error(error) -> {
      io.debug(error)
      wisp.log_error("Failed to chunk and send file")
      Error(error)
    }
  }
}

fn recursive_chunk_and_send(
  options: ClientOptions,
  socket: mug.Socket,
  file_contents: BitArray,
  total_bits: Int,
  index: Int,
) -> Result(Nil, mug.Error) {
  wisp.log_info(":: Sending packet " <> int.to_string(index))

  case index < total_bits {
    True -> {
      let take = case index + options.max_chunk_size <= total_bits {
        True -> options.max_chunk_size
        False -> total_bits - index
      }

      io.debug(total_bits)
      io.debug(index)
      io.debug(take)

      let chunking_result =
        bit_array.slice(from: file_contents, at: index, take: take)

      case chunking_result {
        Ok(chunk) -> {
          // Add the network order byte to the front to indicate the packet length
          let network_order_bytes = <<bit_array.byte_size(chunk):little>>

          let wrapped_chunk =
            network_order_bytes
            |> bit_array.append(chunk)
            |> bit_array.append(<<0:little>>)

          // Send the chunk
          use <- send_bytes(socket, wrapped_chunk)

          wisp.log_info(":: Finished sending packet")

          recursive_chunk_and_send(
            options,
            socket,
            file_contents,
            total_bits,
            index + options.max_chunk_size,
          )
        }
        Error(Nil) -> {
          // TzDO - this error doesn't make sense - need to create
          // our own error model
          Error(mug.Eacces)
        }
      }
    }
    False -> {
      Ok(Nil)
    }
  }
}
