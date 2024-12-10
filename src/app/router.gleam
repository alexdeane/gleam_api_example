import app/clients/clamav/client_options
import app/handlers/health_check
import app/handlers/hello
import app/handlers/upload
import app/web
import glenvy/env
import wisp.{type Request, type Response}

/// Very basic router that routes requests to the correct handler.
pub fn route_request(req: Request) -> Response {
  // Apply the middleware stack for this request/response.
  use _req <- web.middleware(req)

  // TODO initialize db conn
  wisp.log_info("Routing request " <> req.path)

  let assert Ok(clam_hostname) = env.get_string("CLAMAV_HOSTNAME")
  let assert Ok(clam_port) = env.get_int("CLAMAV_PORT")

  let options =
    client_options.ClientOptions(
      host: clam_hostname,
      port: clam_port,
      max_chunk_size: 131_072,
      connection_timeout: 99_999_999,
      reply_timeout: 10_000,
    )

  case req.path {
    "" | "/" -> health_check.handle(options)
    "/hello/" <> name -> hello.handle(name)
    "/upload" | "/upload/" -> upload.handle(req)
    _ -> wisp.not_found()
  }
}
