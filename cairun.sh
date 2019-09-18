#!/bin/bash

DDOS_DIR=~/ddos-detection
CODE_DIR=${DDOS_DIR}/code

DS_DIR=$DDOS_DIR/datasets
DS_NAME=maccdc2012
DS_NAME=caida

NSHOT_DIR=${DS_DIR}/${DS_NAME}
PCAP_DIR=${DS_DIR}/${DS_NAME}

OUT_DIR=${DDOS_DIR}/out-${DS_NAME}
mkdir $OUT_DIR

if [ $1 = netshot ] ; then
  echo "****************************************"
  echo "* Making NetShots **********************"
  TIME=5
  echo "* PCAP Source Dir:       $PCAP_DIR"
  echo "* NShot Destination Dir: $NSHOT_DIR"
  echo "* Time Resolution:       ${TIME}s"

  # echo "* Pipe:                  $PIPE"
  # PIPE=${PCAP_DIR}/p.pcap
  # c="sudo mkfifo $PIPE"
  # echo $c; eval $c

  # echo "sudo chmod 0666 $PIPE"
  # sudo chmod 0666 $PIPE
  # echo "sudo mergecap -F pcap -w -  $PCAP_DIR/res/*.pcap > $PIPE &"
  # sudo mergecap -F pcap -w -  $PCAP_DIR/res/*.pcap > $PIPE &
  # echo "sudo mkdir $NSHOT_DIR"
  # sudo mkdir $NSHOT_DIR

  c="${CODE_DIR}/netshot.py -d $PCAP_DIR -o $NSHOT_DIR -t $TIME > log-nshots.tmp"
  echo $c; eval $c

  # echo "sudo rm $PIPE"
  # sudo rm $PIPE
elif ! [ -z "$1" ] ; then
  T=$1
  echo "t is $T"
fi
if [ -z "$T" ] ; then
  times=( 60 30 20 10 5 )
  # times=( 20 10 5 )
  echo "Running for times 60, 30, 10 and 5 seconds"
  sleep 2
elif ! [[ $T =~ ^[0-9]+$ ]] ; then
  echo "ERROR: The passed argument is not a number \"$T\"" >&2; exit 1
else
  times=$T
fi

for T in "${times[@]}"
do
    echo ""
    echo "      REMOVE *t${T}* FILES IN $OUT_DIR"
    rm $OUT_DIR/*t${T}*
    echo ""
    echo "****************************************"
    echo "* Making Entropies and Statistics ******"
    STATDST="${OUT_DIR}/caidaall_t${T}.stt"
    ENTDST="${OUT_DIR}/caidaall_t${T}.ent"
    LOGFILE="log.tmp"; echo "" > $LOGFILE
    echo "Logging" >> $LOGFILE
    echo "Time Win: ${T} seconds" >> $LOGFILE
    echo "Ent Dest: $ENTDST" >> $LOGFILE
    echo "Stt Dest: $STATDST" >> $LOGFILE


    c="${CODE_DIR}/psim.py -f $NSHOT_DIR -o $OUT_DIR -t $T -e $ENTDST -s $STATDST >> $LOGFILE"
    c="${CODE_DIR}/psim.py -f $NSHOT_DIR -o $OUT_DIR -t $T -e $ENTDST -s $STATDST"
    c="${CODE_DIR}/psim.py -f $NSHOT_DIR -o $OUT_DIR -t $T -e $ENTDST -s $STATDST -i"
    # c="${CODE_DIR}/psim.py -d $PCAP_DIR -o $OUT_DIR -t $T -e $ENTDST -s $STATDST"
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

# TIME=15
# NSHOT_DIR=${DS_DIR}/${DS_NAME}/t$TIME
# mkdir $NSHOT_DIR
# c="${CODE_DIR}/netshot.py -d $PCAP_DIR -o $NSHOT_DIR -t $TIME > log.tmp"
# echo $c; eval $c










