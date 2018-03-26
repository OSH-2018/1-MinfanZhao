#!/bin/bash
echo Hello Linux
echo -n >output.txt
while read line
do
    echo $line >>output.txt
done
