import gleam/erlang/process.{type Subject}
import gleam/otp/actor

pub fn start_handler() -> Subject(FileHandlerMessage) {
  // Create an actor to scan the file in the background
  let assert Ok(actor) = actor.start([], file_handler)
  actor
}

pub type FileHandlerMessage {
  File(BitArray)
  CheckStatus(reply_with: Subject(Result(element, Nil)))
}

fn file_handler(
  message: FileHandlerMessage,
  stack: List(String),
) -> actor.Next(FileHandlerMessage, List(e)) {
  todo
}
