import gleam/json
import wisp.{type Response}

pub fn handle(name: String) -> Response {
  let res = json.object([#("message", json.string("Hello, " <> name))])
  wisp.json_response(json.to_string_tree(res), 200)
}
