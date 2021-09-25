#!/usr/bin/env py3
import sys
import getopt
import re
from utilities import eprint

def parse_arguments (argv):
  
  usage_msg = 'Usage: {} -i <input-text>'.format (argv[0])
  try:
    opts, args = getopt.getopt(argv[1:],"hi:",["help", "infile"])
  except getopt.GetoptError:
    eprint ('ERR: Problem reading arguments.')
    eprint (usage_msg)
    sys.exit(2)
  for opt, arg in opts:
    if opt in ("-h", "--help"):
      eprint (usage_msg)
      eprint ("-h (--help)            Prints this help")
      eprint ("-i (--infile)          Input file")
      sys.exit()
    elif opt in ("-i", "--infile"):
      infile = arg
  else:
    eprint ('WARN: No arguments are passed. Using default values.')
  
  eprint ('Input file =', infile)
  eprint ("")

  return infile

if __name__ == "__main__":
  infile = parse_arguments (sys.argv)

  with open (infile, 'r' ) as f:
    content = f.read()
  oldreg="\033\[31m(.|\n)*?\033\[4m flowCnt"
  newreg="flowCnt"
  c1 = re.sub(oldreg, newreg, content, flags = re.M)

  oldreg=" *\033\[0;32m *"
  newreg="\t"
  c1 = re.sub(oldreg, newreg, c1, flags = re.M)

  oldreg="\033\[m"
  newreg=""
  c1 = re.sub(oldreg, newreg, c1, flags = re.M)
  
  #oldreg="\033\[33mTime.*to "
  oldreg="\nTime.*to "
  newreg="\nTime\t"
  c1 = re.sub(oldreg, newreg, c1, flags = re.M)

  oldreg="flowCnt  newCnt  avgAge  stdAge avgPLen stdPLen avgPPrd stdPPrd"
  newreg="\tflowCnt\tnewCnt\tavgAge\tstdAge\tavgPLen\tstdPLen\tavgPPrd\tstdPPrd"
  c1 = re.sub(oldreg, newreg, c1, flags = re.M)

  oldreg="New cTable created\nEntropy diagram\n"
  newreg=""
  c1 = re.sub(oldreg, newreg, c1, flags = re.M)

  print (c1)