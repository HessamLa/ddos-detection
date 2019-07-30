#!/bin/bash

# alias mystat='qstat -u hessamla'
# alias killjobs='qselect -u hessamla | xargs qdel'

times=( 5 10 30 60 )

# # FOR DEBUG
# rm macrun.sh.*
# times=( 5 )
# echo ~
# NSHOT_DIR=~/datasets/maccdc2012
# echo $NSHOT_DIR
# DBG_FLG='-q debug'

for T in "${times[@]}"
do
    c="qsub $DBG_FLG -l nodes=1:ppn=1,vmem=20gb,walltime=336:00:00 macrun.sh -v T=$T"
    echo $c
    eval $c
done
