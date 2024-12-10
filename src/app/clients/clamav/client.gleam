import app/clients/clamav/commands/instream as ins
import app/clients/clamav/commands/ping as p

pub fn instream(options, file_content) {
  ins.instream(options, file_content)
}

pub fn ping(options) {
  p.ping(options)
}
