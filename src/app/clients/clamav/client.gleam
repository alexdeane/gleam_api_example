import app/clients/clamav/clam_scan_data.{type ClamScanData, Clean}
import gleam/bit_array
import gleam/bytes_tree.{type BytesTree}
import gleam/erlang/os
import gleam/list
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
  // This may not be necessary
  let padded_file_contents = bit_array.pad_to_bytes(file_contents)

  // Initialize socket with a command
  use socket <- execute_clam_command(options, "INSTREAM")

  // Send the file contents
  use <- chunk_and_send_file(options, socket, padded_file_contents)

  // Receive the response
  use response_bytes <- receive_bytes(socket, options.reply_timeout)

  // todo as "Parse the response from the resulting bytes"
  Ok(Clean)
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
  let send_result =
    recursive_chunk_and_send(
      options,
      socket,
      file_contents,
      bit_array.bit_size(file_contents),
      0,
    )

  case send_result {
    Ok(_) -> {
      callback()
    }
    Error(error) -> {
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
  case index < total_bits {
    True -> {
      let chunking_result =
        bit_array.slice(
          from: file_contents,
          at: index,
          take: options.max_chunk_size,
        )

      case chunking_result {
        Ok(chunk) -> {
          // Send the network order bytes
          // var readBytes = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(readByteCount)); 
          // convert readByteCount to NetworkOrder!
          // await clamStream.WriteAsync(readBytes, 0, readBytes.Length, cancellationToken).ConfigureAwait(false);
          use <- send_bytes(socket, chunk)

          recursive_chunk_and_send(
            options,
            socket,
            file_contents,
            total_bits,
            index + options.max_chunk_size,
          )
        }
        Error(_) -> {
          // TODO - this error doesn't make sense - need to create
          // our own error model
          Error(mug.Econnaborted)
        }
      }
    }
    False -> {
      Ok(Nil)
    }
  }
}
