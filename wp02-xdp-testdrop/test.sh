#!/bin/bash
while :           #冒号表述死循环 同while (true)
do
    sudo bpftool map dump id 27
    sleep 1
done
