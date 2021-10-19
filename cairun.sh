#!/bin/bash

#SBATCH -J caida_t10
#SBATCH -p gpu
#SBATCH -o log_%j.txt
#SBATCH -e log_%j.err
#SBATCH --nodes=1
#SBATCH --time=8:00:00
#SBATCH --ntasks-per-node=5
#SBATCH --cpus-per-task=1
#SBATCH --mem=160G

DDOS_DIR=~/ddos-detection
CODE_DIR=${DDOS_DIR}/src

DS_NAME=maccdc2012
DS_NAME=caida
DS_NAME=cicddos2019
DS_NAME=test_cicddos2019

DS_DIR=$DDOS_DIR/datasets/$DS_NAME

PCAP_DIR=${DS_DIR}/pcap
FTD_DIR=${DS_DIR}/ftd-t5

OUT_DIR=${DS_DIR}/output

if [[ $1 = pcap2ftd ]] ; then
  date
  echo "****************************************"
  echo "* Making FTD Shots **********************"
  TIME=5
  FTD_DIR=${DS_DIR}/ftd-t${TIME}
  mkdir -p $FTD_DIR
  echo "* PCAP Source Dir:     $PCAP_DIR"
  echo "* FTD Destination Dir: $FTD_DIR"
  echo "* Time Resolution:     ${TIME}s"
  # echo "* Pipe:                  $PIPE"
  # PIPE=${PCAP_DIR}/p.pcap
  # c="sudo mkfifo $PIPE"
  # echo $c; eval $c

  # echo "sudo chmod 0666 $PIPE"
  # sudo chmod 0666 $PIPE
  # echo "sudo mergecap -F pcap -w -  $PCAP_DIR/res/*.pcap > $PIPE &"
  # sudo mergecap -F pcap -w -  $PCAP_DIR/res/*.pcap > $PIPE &
  # echo "sudo mkdir $FTD_DIR"
  # sudo mkdir $FTD_DIR

  c="${CODE_DIR}/pcap2ftd.py -p $PCAP_DIR -o $FTD_DIR -t $TIME > log-ftdshots-t${TIME}.tmp"
  # c="srun -n 1 $c"  # this line is added for slurm job manager
  echo $c;
  eval $c

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
    date
    echo ""
    echo "****************************************"
    echo "      REMAKE $OUT_DIR"
    OUT_DIR=${DS_DIR}/output-t${T}
    rm -rf $OUT_DIR
    mkdir -p $OUT_DIR
    echo ""
    echo "* Make Entropies and Statistics ******"
    STATDST="${OUT_DIR}/stats.stt"
    ENTDST="${OUT_DIR}/entropies.ent"
    mkdir -p logs
    LOGFILE="logs/log-t${T}.tmp"; echo "" > $LOGFILE
    echo "Logging" >> $LOGFILE
    echo "Time Win: ${T} seconds" >> $LOGFILE
    echo "Ent Dest: $ENTDST" >> $LOGFILE
    echo "Stt Dest: $STATDST" >> $LOGFILE


    c="${CODE_DIR}/psim.py -f $FTD_DIR -o $OUT_DIR -t $T -e $ENTDST -s $STATDST"
    # c="${CODE_DIR}/psim.py -f $FTD_DIR -o $OUT_DIR -t $T -e $ENTDST -s $STATDST"
    # c="${CODE_DIR}/psim.py -f $FTD_DIR -o $OUT_DIR -t $T -e $ENTDST -s $STATDST -i"
    # c="${CODE_DIR}/psim.py -d $PCAP_DIR -o $OUT_DIR -t $T -e $ENTDST -s $STATDST"
    # c="${CODE_DIR}/psim.py -f $FTD_DIR -t $T -e $ENTDST"
    c="$c >> $LOGFILE"  # send the output to logfile
    c="srun -n 1 $c"    # to make sure each job has its own processor, it is best to use srun -n 1
    c="$c &"            # Finally send the program to background
    echo "* |Time Window             ${T}s"
    echo "* |NShot Source Dir        $FTD_DIR"
    echo "* |Entropies Destination   $ENTDST"
    echo "* |Statistics Destination  $STATDST"
    echo "* |$c" 
    echo "*"
    eval $c
done

# TIME=15
# FTD_DIR=${DS_DIR}/${DS_NAME}/t$TIME
# mkdir $FTD_DIR
# c="${CODE_DIR}/ftdshot.py -d $PCAP_DIR -o $FTD_DIR -t $TIME > log.tmp"
# echo $c; eval $c

wait # this line is added for slurm job manager
date










