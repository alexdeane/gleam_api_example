pub type ClientOptions {
  ClientOptions(
    host: String,
    port: Int,
    max_chunk_size: Int,
    connection_timeout: Int,
    reply_timeout: Int,
  )
}
