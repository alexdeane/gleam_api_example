import app/clients/clamav/client_options.{type ClientOptions}
import app/clients/clamav/common/clam
import app/clients/clamav/common/tcp
import app/clients/clamav/results.{
  type ClamError, CannotParseResponse, ConnectionError,
}
import gleam/bit_array
import gleam/result

/// Send a PING command to the ClamAV server
pub fn ping(options: ClientOptions) -> Result(Nil, ClamError) {
  let res =
    {
      use socket <- clam.execute_command(options, "PING")
      use res <- tcp.receive_bytes(socket, options.reply_timeout)
      Ok(res)
    }
    |> result.try_recover(with: fn(e) { Error(ConnectionError(e)) })

  case res {
    Ok(bits) -> {
      let response_text = bits |> bit_array.to_string()
      case response_text {
        Ok("PONG") -> Ok(Nil)
        Ok(text) -> Error(CannotParseResponse(text))
        _ -> Error(CannotParseResponse("UNKNOWN"))
      }
    }
    Error(error) -> Error(error)
  }
}
