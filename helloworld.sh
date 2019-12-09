#!/bin/sh
msg="Debasish"
echo "hello world $msg"

#pwd

#ls -l
scp -i cloudinfra_key.pem -o "StrictHostKeyChecking no" ./bootstrap.sh  ubuntu@54.166.166.152:~
ssh -i cloudinfra_key.pem -o "StrictHostKeyChecking no"  ubuntu@54.166.166.152 "chmod +x bootstrap.sh; ./bootstrap.sh"