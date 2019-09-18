#!/bin/bash

# echo | ./test.py


times=( 60 30 10 5 )
nums=( 1 2 3 4 5 6 7 8 9 )
for T in "${times[@]}"
do
    for num in "${nums[@]}"
    do
        ./code/entropy_diagram.py -w 4000 -e SrcIP,DstIP,PktCntCtgry -s ./figures/caida-t${T}-k${num} ./out-caida/1/caida-t${T}-cftbl-new-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-old-k${num}.ent ./out-caida/1/caida-t${T}-cftbl-any-k${num}.ent
    done


done

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
