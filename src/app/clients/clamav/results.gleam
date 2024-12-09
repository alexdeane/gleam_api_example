import mug

pub type ClamScanResult {
  Clean
  VirusDetected(infected_files: List(InfectedFile))
}

pub type InfectedFile {
  InfectedFile(file_name: String, virus_name: String)
}

pub type ClamError {
  ScanError(error: String)
  CannotParseResponse(response: String)
  ConnectionError(error: mug.Error)
}
