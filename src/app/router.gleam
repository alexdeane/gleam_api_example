import app/handlers/health_check
import app/handlers/hello
import app/web
import wisp.{type Request, type Response}

/// Very basic router that routes requests to the correct handler.
pub fn route_request(req: Request) -> Response {
  // Apply the middleware stack for this request/response.
  use req <- web.middleware(req)

  wisp.log_info("Routing request " <> req.path)

  case req.path {
    "" | "/" -> health_check.handle()
    "/hello/" <> name -> hello.handle(name)
    _ -> wisp.not_found()
  }
}
