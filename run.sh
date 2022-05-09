#!/bin/bash

# echo | ./test.py


times=( 60 30 15 10 5 )
patterns=( 'SAT-01-12' 'SAT-03-11' )
for TWIN in "${times[@]}"
do
    for PATTERN in "${patterns[@]}"
    do
        LOG_NAME=log-${PATTERN}-t${TWIN}
        c="python3 -u show.py $PATTERN $TWIN"
        c="srun -p gpu -o ${LOG_NAME}.txt -e ${LOG_NAME}.err --time=8:00:00 $c &"
        echo $c
        eval $c
    done
done

# PATTERN=SAT-01-12; TWIN=10; LOG_NAME=log-${PATTERN}-t${TWIN}; srun -p gpu -o ${LOG_NAME}.txt -e ${LOG_NAME}.err --time=8:00:00 python3 show.py $PATTERN $TWIN &
# PATTERN=SAT-01-12; TWIN=15; LOG_NAME=log-${PATTERN}-t${TWIN}; srun -p gpu -o ${LOG_NAME}.txt -e ${LOG_NAME}.err --time=8:00:00 python3 show.py $PATTERN $TWIN &
# PATTERN=SAT-01-12; TWIN=20; LOG_NAME=log-${PATTERN}-t${TWIN}; srun -p gpu -o ${LOG_NAME}.txt -e ${LOG_NAME}.err --time=8:00:00 python3 show.py $PATTERN $TWIN &
# PATTERN=SAT-01-12; TWIN=30; LOG_NAME=log-${PATTERN}-t${TWIN}; srun -p gpu -o ${LOG_NAME}.txt -e ${LOG_NAME}.err --time=8:00:00 python3 show.py $PATTERN $TWIN &
# PATTERN=SAT-01-12; TWIN=60; LOG_NAME=log-${PATTERN}-t${TWIN}; srun -p gpu -o ${LOG_NAME}.txt -e ${LOG_NAME}.err --time=8:00:00 python3 show.py $PATTERN $TWIN &
                                    #  log-                                                                                                                                                                  
# PATTERN=SAT-03-11; TWIN=10; LOG_NAME=log-${PATTERN}-t${TWIN}; srun -p gpu -o ${LOG_NAME}.txt -e ${LOG_NAME}.err --time=8:00:00 python3 show.py $PATTERN $TWIN &
# PATTERN=SAT-03-11; TWIN=15; LOG_NAME=log-${PATTERN}-t${TWIN}; srun -p gpu -o ${LOG_NAME}.txt -e ${LOG_NAME}.err --time=8:00:00 python3 show.py $PATTERN $TWIN &
# PATTERN=SAT-03-11; TWIN=20; LOG_NAME=log-${PATTERN}-t${TWIN}; srun -p gpu -o ${LOG_NAME}.txt -e ${LOG_NAME}.err --time=8:00:00 python3 show.py $PATTERN $TWIN &
# PATTERN=SAT-03-11; TWIN=30; LOG_NAME=log-${PATTERN}-t${TWIN}; srun -p gpu -o ${LOG_NAME}.txt -e ${LOG_NAME}.err --time=8:00:00 python3 show.py $PATTERN $TWIN &
# PATTERN=SAT-03-11; TWIN=60; LOG_NAME=log-${PATTERN}-t${TWIN}; srun -p gpu -o ${LOG_NAME}.txt -e ${LOG_NAME}.err --time=8:00:00 python3 show.py $PATTERN $TWIN &


# num=1
# ./code/entropy_diagram.py -w 4000 -e SrcIP,DstIP -s ./figures/caida-t${T}-k${num} ./out-caida/1/caida-t${T}-cftbl-new-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-old-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-any-k${num}.ent
# num=2
# ./code/entropy_diagram.py -w 4000 -e SrcIP,DstIP -s ./figures/caida-t${T}-k${num} ./out-caida/1/caida-t${T}-cftbl-new-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-old-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-any-k${num}.ent
# num=3
# ./code/entropy_diagram.py -w 4000 -e SrcIP,DstIP -s ./figures/caida-t${T}-k${num} ./out-caida/1/caida-t${T}-cftbl-new-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-old-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-any-k${num}.ent
# num=4
# ./code/entropy_diagram.py -w 4000 -e SrcIP,DstIP -s ./figures/caida-t${T}-k${num} ./out-caida/1/caida-t${T}-cftbl-new-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-old-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-any-k${num}.ent
# num=5
# ./code/entropy_diagram.py -w 4000 -e SrcIP,DstIP -s ./figures/caida-t${T}-k${num} ./out-caida/1/caida-t${T}-cftbl-new-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-old-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-any-k${num}.ent
# num=6
# ./code/entropy_diagram.py -w 4000 -e SrcIP,DstIP -s ./figures/caida-t${T}-k${num} ./out-caida/1/caida-t${T}-cftbl-new-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-old-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-any-k${num}.ent
# num=7
# ./code/entropy_diagram.py -w 4000 -e SrcIP,DstIP -s ./figures/caida-t${T}-k${num} ./out-caida/1/caida-t${T}-cftbl-new-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-old-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-any-k${num}.ent
# num=8
# ./code/entropy_diagram.py -w 4000 -e SrcIP,DstIP -s ./figures/caida-t${T}-k${num} ./out-caida/1/caida-t${T}-cftbl-new-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-old-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-any-k${num}.ent
# num=9
# ./code/entropy_diagram.py -w 4000 -e SrcIP,DstIP -s ./figures/caida-t${T}-k${num} ./out-caida/1/caida-t${T}-cftbl-new-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-old-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-any-k${num}.ent
