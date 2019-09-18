#!/bin/bash

DDOS_DIR=~/ddos-detection
CODE_DIR=${DDOS_DIR}/code

DS_DIR=$DDOS_DIR/datasets
DS_NAME=maccdc2012
DS_NAME=caida

NSHOT_DIR=${DS_DIR}/${DS_NAME}
PCAP_DIR=${DS_DIR}/${DS_NAME}

OUT_DIR=${DDOS_DIR}/out-temp
mkdir $OUT_DIR
rm $OUT_DIR/*

# echo "****************************************"
# echo "* Making NetShots **********************"
TIME=5
PIPE=${PCAP_DIR}/p.pcap
echo "* PCAP Source Dir:       $PCAP_DIR"
echo "* NShot Destination Dir: $NSHOT_DIR"
echo "* Pipe:                  $PIPE"
echo "* Time Resolution:       ${TIME}s"
# echo "sudo mkfifo $PIPE"
# sudo mkfifo $PIPE
# echo "sudo chmod 0666 $PIPE"
# sudo chmod 0666 $PIPE
# echo "sudo mergecap -F pcap -w -  $PCAP_DIR/res/*.pcap > $PIPE &"
# sudo mergecap -F pcap -w -  $PCAP_DIR/res/*.pcap > $PIPE &
# echo "sudo mkdir $NSHOT_DIR"
# sudo mkdir $NSHOT_DIR

# echo "$CODE_DIR/netshot.py -d $PCAP_DIR -o $NSHOT_DIR -t $TIME > log.tmp"
# $CODE_DIR/netshot.py -d $PCAP_DIR -o $NSHOT_DIR -t $TIME > log.tmp

# echo "sudo rm $PIPE"
# sudo rm $PIPE

times=( 60 30 10 5 )
times=( 30 )

if ! [ -z "$1" ] ; then
  T=$1
  echo "t is $T"
fi
if [ -z "$T" ] ; then
  echo "Running for times ${times[@]} seconds"
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
    STATDST="${OUT_DIR}/${DS_NAME}all_t${T}.stt"
    ENTDST="${OUT_DIR}/${DS_NAME}all_t${T}.ent"
    c="${CODE_DIR}/psim.py -f $NSHOT_DIR -o $OUT_DIR -t $T -e $ENTDST -s $STATDST > log.tmp"
    c="${CODE_DIR}/psim.py -f $NSHOT_DIR -o $OUT_DIR -t $T -e $ENTDST -s $STATDST -i > log.tmp"
    c="${CODE_DIR}/psim.py -f $NSHOT_DIR -o $OUT_DIR -t $T -e $ENTDST -s $STATDST -i"
    # c="${CODE_DIR}/psim.py -f $NSHOT_DIR -t $T -i "#-e $ENTDST"
    # c="${CODE_DIR}/psim.py -d $PCAP_DIR -t $T -i "
    # c="${CODE_DIR}/psim.py -f $NSHOT_DIR -t $T -i "
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



















