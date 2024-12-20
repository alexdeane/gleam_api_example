/// Options for the ClamAV client
pub type ClamAvClientOptions {
  ClamAvClientOptions(
    host: String,
    port: Int,
    max_chunk_size: Int,
    connection_timeout: Int,
    reply_timeout: Int,
  )
}
