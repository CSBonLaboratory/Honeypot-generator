#!/bin/bash

PROMPT="${USER}:${HOSTNAME}:`pwd`# "
while read -p $PROMPT line
do
    echo $line >> $HISTFILE
    #echo $line
    /bin/bash -c "${line} $1 $2 $3"
done