#!/bin/bash
SRUN_DBG=""
if [ -z "$1" ]; then
  if [ "$1" == 'debug' ]; then
    SRUN_DBG="-debug"
  fi
fi

C_METHODS_FIELDS="none,any"
CMETHODS=( catlog2 catlog10 catloge );
CFIELDS=( pktcnt pktlen );

for CMETHOD   in "${CMETHODS[@]}";  do
for CFIELD    in "${CFIELDS[@]}";   do
  C_METHODS_FIELDS="${C_METHODS_FIELDS} ${CMETHOD},${CFIELD} "
done; done;

# echo $C_METHODS_FIELDS
# turn string sequence into array
IFS=' ' read -r -a C_METHODS_FIELDS <<< "$C_METHODS_FIELDS";

DURATION=1-23:59:59;
PATTERNS=( SAT-01-12 SAT-03-11 );
TWINS=( 5 10 15 20 30 60 );

for CMF       in ${C_METHODS_FIELDS[@]}; do
  OLDIFS=$IFS;  IFS=',';
  set -- $CMF;
  CMETHOD=$1;
  CFIELD=$2;
  IFS=$OLDIFS;
for TWIN      in "${TWINS[@]}";     do
for PATTERN   in "${PATTERNS[@]}";  do
  LOG_NAME=./log/log-${PATTERN}-${CMETHOD}-${CFIELD}-t${TWIN};
  
  c="python3 script.py -p $PATTERN -m $CMETHOD -f $CFIELD -t $TWIN";
  c="srun -p gpu -o ${LOG_NAME}.txt -e ${LOG_NAME}.err --time=$DURATION $c";
  c="$c &" # run in parallel
  
  echo $c;
  eval $c;
done; done; done;
