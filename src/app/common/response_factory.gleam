import gleam/json
import gleam/list
import wisp

pub fn bad_request(message: String) -> wisp.Response {
  error(400, message)
}

fn error(status_code: Int, message: String) -> wisp.Response {
  create(status_code, [#("error", message)])
}

fn create(code: Int, properties: List(#(String, String))) -> wisp.Response {
  let as_json =
    json.object(
      properties
      |> list.map(fn(t) {
        let #(k, v) = t
        #(k, json.string(v))
      }),
    )

  wisp.json_response(json.to_string_tree(as_json), code)
}
