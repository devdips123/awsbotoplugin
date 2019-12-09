#!/bin/sh

scp -i cloudinfra_key.pem -o "StrictHostKeyChecking no" ubuntu@18.206.155.96:~/blast_example/results.txt ./blast_log.txt   > /dev/null
if [ $? -eq "0" ]
then
    echo "[INFO] log file successfully imported"
    return 0
else
    echo "[ERROR] error in log transfer"
    return 1
fi