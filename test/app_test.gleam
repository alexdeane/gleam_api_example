import app/handlers/health_check
import gleeunit
import gleeunit/should
import wisp

/// Run with `gleam test`
pub fn main() {
  gleeunit.main()
}

// gleeunit test functions end in `_test`
pub fn health_check_test() {
  health_check.handle()
  |> should.equal(wisp.ok())
}
