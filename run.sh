#!/bin/bash

# echo | ./test.py

# caida with time 15
# TIME=15
# NSHOT_DIR=./nshot_caida_t$TIME
# PCAP_DIR=/home/datasets/caida/
# mkdir $NSHOT_DIR
# ./netshot.py -d $PCAP_DIR -o $NSHOT_DIR -t $TIME
# ./psim.py -f $NSHOT_DIR -t $TIME 
# mv entropies.dmp entropies_caida_$TIME

# caida with time 30
# TIME=30
# NSHOT_DIR=./nshot_caida_t$TIME
# PCAP_DIR=/home/datasets/caida/ddos-20070804/
# mkdir $NSHOT_DIR
# ./netshot.py -d $PCAP_DIR -o $NSHOT_DIR -t $TIME 
# ./psim.py -f $NSHOT_DIR -t $TIME 
# mv entropies.dmp entropies_caida_$TIME

# maccdc with time 15
# TIME=15
# NSHOT_DIR=./nshot_maccdc_t$TIME
# PCAP_DIR=/home/datasets/maccdc2012/
# mkdir $NSHOT_DIR
# ./netshot.py -d $PCAP_DIR -o $NSHOT_DIR -t $TIME 
# ./psim.py -f $NSHOT_DIR -t $TIME 
# mv entropies.dmp entropies_maccdc_$TIME.dmp

# # maccdc with time 30
# TIME=30
# NSHOT_DIR=./nshot_maccdc_t$TIME
# PCAP_DIR=/home/datasets/maccdc2012/
# mkdir $NSHOT_DIR
# ./netshot.py -d $PCAP_DIR -o $NSHOT_DIR -t $TIME 
# ./psim.py -f $NSHOT_DIR -t $TIME 
# mv entropies.dmp entropies_maccdc_$TIME.dmp

# ./psim.py -t 30 -d /home/datasets/caida/0 -e ./dmps/ent_caida0.dmp &
# ./psim.py -t 30 -d /home/datasets/caida/1 -e ./dmps/ent_caida1.dmp &
# ./psim.py -t 30 -d /home/datasets/caida/2 -e ./dmps/ent_caida2.dmp &
# ./psim.py -t 30 -d /home/datasets/caida/3 -e ./dmps/ent_caida3.dmp &
# ./psim.py -t 30 -d /home/datasets/caida/ddos-20070804 -e ./dmps/ent_caidaall.dmp &
# ./psim.py -t 30 -d /home/datasets/caida/ -i -e ./dmps/ent_caidaall.dmp

# TIME=10
# ./psim.py -t $TIME -d /home/datasets/caida/ -e ./dmps/ent${TIME}_caidaall.dmp > ./dmps/stat${TIME}_caidaall.txt

TIME=5
./psim.py -t $TIME -d /home/datasets/caida/ -i


# # caida with time 5
TIME=5
NSHOT_DIR=./nshot_caidaall_t$TIME
PCAP_DIR=/home/datasets/caida/
# mkdir $NSHOT_DIR
# ./netshot.py -d $PCAP_DIR -o $NSHOT_DIR -t $TIME > log.tmp
# ./psim.py -f $NSHOT_DIR -t $TIME -i

# T=5
# ./psim.py -f $NSHOT_DIR -t $T -e ./dmps/ent${T}_caidaall.dmp > ./dmps/stat${T}_caidaall.txt

# T=10
# ./psim.py -f $NSHOT_DIR -t $T -e ./dmps/ent${T}_caidaall.dmp > ./dmps/stat${T}_caidaall.txt

# T=30
# ./psim.py -f $NSHOT_DIR -t $T -e ./dmps/ent${T}_caidaall.dmp > ./dmps/stat${T}_caidaall.txt

# T=60
# ./psim.py -f $NSHOT_DIR -t $T -e ./dmps/ent${T}_caidaall.dmp > ./dmps/stat${T}_caidaall.txt

T=5
NAME=stat${T}_log2_caidaall.txt
./psim.py -f $NSHOT_DIR -t $T  #> ./dmps/$NAME

T=10
NAME=stat${T}_log2_caidaall.txt
./psim.py -f $NSHOT_DIR -t $T  #> ./dmps/$NAME

T=30
NAME=stat${T}_log2_caidaall.txt
./psim.py -f $NSHOT_DIR -t $T  #> ./dmps/$NAME

T=60
NAME=stat${T}_log2_caidaall.txt
./psim.py -f $NSHOT_DIR -t $T  #> ./dmps/$NAME
