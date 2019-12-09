#!/bin/sh

scp -i cloudinfra_key.pem -o "StrictHostKeyChecking no" ./bootstrap.sh  ubuntu@18.206.155.96:~ > /dev/null
[ "$? == 0" ] && echo "bootstrap.sh successfully copied"
ssh -i cloudinfra_key.pem -o "StrictHostKeyChecking no"  ubuntu@18.206.155.96 "chmod +x bootstrap.sh; ./bootstrap.sh"
if [ $? -eq "0" ]
then
    echo "[INFO] Benchmark successfully executed"
    return 0
else
    echo "[ERROR] Error occurred while executing benchmark"
    return 1
fi