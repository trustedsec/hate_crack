#!/usr/bin/env python

import sys
import os
import subprocess
import shutil

splitlen_bin = "hashcat-utils/bin/splitlen.app"
rli_bin = "hashcat-utils/bin/rli.app"

# Help
def usage():
  print "usage: python %s <input file list> <output directory>" % sys.argv[0]

def lineCount(file):
  try:
    outFile = open(file)
  except:
    return 0

  count = 0
  for line in outFile:
    count = count + 1
  return count

# Main guts
def main():
  try:
    input_list = open(sys.argv[1], "r")
    destination = sys.argv[2]

  except IndexError:
    usage()
    sys.exit()
    
  # Get list of wordlists from <input file list> argument  
  for wordlist in input_list:
    print wordlist.strip()
    
    # Parse wordlists by password length into "optimized" <output directory>
    if len(os.listdir(destination)) == 0:
      splitlenProcess = subprocess.Popen("%s %s < %s" % (splitlen_bin, destination, wordlist), shell=True).wait()
    else:
      if not os.path.isdir("/tmp/splitlen"):
        os.mkdir("/tmp/splitlen")
      splitlenProcess = subprocess.Popen("%s /tmp/splitlen < %s" % (splitlen_bin, wordlist), shell=True).wait()

			# Copy unique passwords into "optimized" <output directory>
      for file in os.listdir("/tmp/splitlen"):
        if not os.path.isfile(destination + "/" + file):
          shutil.copyfile(file, destination)
        else:
          rliProcess = subprocess.Popen("%s /tmp/splitlen/%s /tmp/splitlen.out %s/%s" % (rli_bin, file, destination, file), shell=True).wait()
          if lineCount("/tmp/splitlen.out") > 0:
            destination_file = open(destination + "/" + file, "a")
            splitlen_file = open("/tmp/splitlen.out", "r")
            destination_file.write(splitlen_file.read())
            destination_file.close()
            splitlen_file.close()
            
    # Clean Up
    if os.path.isdir("/tmp/splitlen"):
      shutil.rmtree('/tmp/splitlen')
    if os.path.isfile("/tmp/splitlen.out"):
      os.remove("/tmp/splitlen.out")


# Standard boilerplate to call the main() function
if __name__ == '__main__':
  main()
