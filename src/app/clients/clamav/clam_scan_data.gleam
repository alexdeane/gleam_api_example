pub type ClamScanData {
  Clean
  VirusDetected(virus_name: String, details: String)
}

pub type ClamError {
  ConnectionFailed
  Timeout
}
