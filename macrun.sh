#!/bin/bash


DDOS_DIR=~/ddos-detection
CODE_DIR=${DDOS_DIR}/code
DMPS_DIR=${DDOS_DIR}/dmps

DS_DIR=$DDOS_DIR/datasets
NSHOT_DIR=${DS_DIR}/maccdc2012
PCAP_DIR=${DS_DIR}/maccdc2012

# echo "****************************************"
# echo "* Making NetShots **********************"
TIME=5
# PIPE=${PCAP_DIR}/p.pcap
# echo "* PCAP Source Dir:       $PCAP_DIR"
# echo "* NShot Destination Dir: $NSHOT_DIR"
# echo "* Pipe:                  $PIPE"
# echo "* Time Resolution:       ${TIME}s"
# echo "sudo mkfifo $PIPE"
# sudo mkfifo $PIPE
# echo "sudo chmod 0666 $PIPE"
# sudo chmod 0666 $PIPE
# echo "sudo mergecap -F pcap -w -  $PCAP_DIR/res/*.pcap > $PIPE &"
# sudo mergecap -F pcap -w -  $PCAP_DIR/res/*.pcap > $PIPE &
# echo "sudo mkdir $NSHOT_DIR"
# sudo mkdir $NSHOT_DIR
# echo "./netshot.py -d $PCAP_DIR -o $NSHOT_DIR -t $TIME > log.tmp"
# ./netshot.py -d $PCAP_DIR -o $NSHOT_DIR -t $TIME > log.tmp
# echo "sudo rm $PIPE"
# sudo rm $PIPE

if ! [ -z "$1" ] ; then
  T=$1
  echo "t is $T"
fi
if [ -z "$T" ] ; then
  times=( 5 10 30 60 )
  echo "Running for times 5, 10, 30 and 60 seconds"
  sleep 2
elif ! [[ $T =~ ^[0-9]+$ ]] ; then
  echo "ERROR: The passed argument is not a number \"$T\"" >&2; exit 1
else
  times=$T
fi

for T in "${times[@]}"
do
    echo "****************************************"
    echo "* Making Entropies and Statistics ******"
    STATDST="${DMPS_DIR}/stat_log2_maccdcall_t${T}.txt"
    ENTDST="${DMPS_DIR}/ent_maccdcall_t${T}.dmp"
    c="${CODE_DIR}/psim.py -f $NSHOT_DIR -t $T -e $ENTDST > $STATDST"
    # c="${CODE_DIR}/psim.py -f $NSHOT_DIR -t $T -e $ENTDST"
    echo "* |Time Window             ${T}s"
    echo "* |NShot Source Dir        $NSHOT_DIR"
    echo "* |Entropies Destination   $ENTDST"
    echo "* |Statistics Destination  $STATDST"
    echo "* |$c"
    echo "*"
    eval $c
    # ./psim.py -f $NSHOT_DIR -t $T -e $ENTDST > $STATDST
    # $sleep 5
done
