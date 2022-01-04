#!/usr/bin/env python3

import sys
import os
import subprocess
import shutil
import pathlib

# Help
def usage():
  print("usage: python %s <input file list> <output directory>" % sys.argv[0])

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
    if not os.path.isfile(sys.argv[1]):
      print('{0} is not a valid file.\n'.format(sys.argv[1]))
      sys.exit()
    if not os.path.isdir(sys.argv[2]):
      create_directory = input('{0} is not a directory. Do you want to create it? (Y or N)'.format(sys.argv[2]))
      if create_directory.upper() == 'Y':
        try:
          pathlib.Path(sys.argv[2]).mkdir(parents=True, exist_ok=True)
        except PermissionError:
          print('You do not have the correct permissions to receate the directory. Please try a different path or create manually')
          sys.exit()
      else:
        print('Please specify a valid directory and try again')
        sys.exit()
    input_list = open(sys.argv[1], "r")
    destination = sys.argv[2]
  except IndexError:
    usage()
    sys.exit()

  # Windows compatability
  if sys.platform == 'darwin':
    splitlen_bin = "hashcat-utils/bin/splitlen.app"
    rli_bin = "hashcat-utils/bin/rli.app"
  elif sys.platform == 'win32':
    dir_separator = "\\"
    splitlen_dir = r"tmp\splitlen"
    splitlen_out = r"tmp\splitlen.out"
    splitlen_bin = r"hashcat-utils\bin\splitlen.exe"
    rli_bin = r"hashcat-utils\bin\rli.exe"    
  else:
    dir_separator = "/"
    splitlen_dir = "/tmp/splitlen"
    splitlen_out = "/tmp/splitlen.out"
    splitlen_bin = "hashcat-utils/bin/splitlen.bin"
    rli_bin = "hashcat-utils/bin/rli.bin"

  # Get list of wordlists from <input file list> argument
  for wordlist in input_list:
    print(wordlist.strip())
    
    # Parse wordlists by password length into "optimized" <output directory>
    if len(os.listdir(destination)) == 0:
      splitlenProcess = subprocess.Popen("%s %s < %s" % (splitlen_bin, destination, wordlist), shell=True).wait()
    else: 
      if not os.path.isdir(splitlen_dir):
        os.makedirs(splitlen_dir)
      splitlenProcess = subprocess.Popen("%s %s < %s" % (splitlen_bin, splitlen_dir, wordlist), shell=True).wait()

      # Copy unique passwords into "optimized" <output directory>
      for file in os.listdir(splitlen_dir):
        if not os.path.isfile(destination + dir_separator + file):
          shutil.copyfile(splitlen_dir + dir_separator + file, destination + dir_separator + file)
        else:
          rliProcess = subprocess.Popen("%s %s%s%s %s %s%s%s" % (rli_bin, splitlen_dir, dir_separator, file, splitlen_out, destination, dir_separator, file), shell=True).wait()
          if lineCount(splitlen_out) > 0:
            destination_file = open(destination + dir_separator + file, "a")
            splitlen_file = open(splitlen_out, "r")
            destination_file.write(splitlen_file.read())
            destination_file.close()
            splitlen_file.close()
            
    # Clean Up
    if os.path.isdir(splitlen_dir):
      shutil.rmtree(splitlen_dir)
    if os.path.isfile(splitlen_out):
      os.remove(splitlen_out)


# Standard boilerplate to call the main() function
if __name__ == '__main__':
  main()
