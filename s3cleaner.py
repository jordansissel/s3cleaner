#!/usr/bin/env python
# 
# Find or delete files in S3 older than a given age and matching a pattern
# Useful for cleaning up old backups, etc.
#

from boto.s3.connection import S3Connection
import time
from optparse import OptionParser
import sys
import re

def main(args):
  parser = OptionParser()
  parser.add_option("--key", dest="key", metavar="KEY",
                    help="AWS Access Key")
  parser.add_option("--secret", dest="secret", metavar="SECRET",
                    help="AWS Access Secret Key")
  parser.add_option("--maxage", dest="maxage", metavar="SECONDS",
                    help="Max age a key(file) can have before we want to delete it")
  parser.add_option("--regex", dest="regex", metavar="REGEX",
                    help="Only consider keys matching this REGEX")
  parser.add_option("--delete", dest="delete", metavar="REGEX", action="store_true",
                    default=False, help="Actually do a delete. If not specified, just list the keys found that match.")
  (config, args) = parser.parse_args(args)

  config_ok = True
  for flag in ("key", "secret", "maxage", "regex"):
    if getattr(config, flag) is None:
      print >>sys.stderr, "Missing required flag: --%s" % flag
      config_ok = False

  if not config_ok:
    print >>sys.stderr, "Configuration is not ok, aborting..."
    return 1

  s3 = S3Connection(config.key, config.secret)

  config.maxage = int(config.maxage)
  config.regex = re.compile(config.regex)

  bucket = s3.get_bucket("logdog-unfuddle-backups")
  for key in bucket.list():
    mtime = time.mktime(time.strptime(key.last_modified.split(".")[0], "%Y-%m-%dT%H:%M:%S"))
    now = time.time()
    if mtime > (now - config.maxage):
      # Skip, file is young enough
      continue
    if config.regex.search(key.name) is None:
      # Skip, file does not match the pattern
      continue
    if config.delete:
      print "Deleting: s3://%s/%s" % (bucket.name, key.name)
      print "  Key has age %d, older than --maxage %d" % (now - mtime, config.maxage)
      print "  Key matches pattern /%s/" % (config.regex.pattern)
      key.delete()
    else:
      print "s3://%s/%s" % (bucket.name, key.name)

if __name__ == '__main__':
  sys.exit(main(sys.argv))
