#!/bin/bash

TodayIs=$(date +%Y-%m-%d)
ABSOLUTE_FILENAME=`readlink -e "$0"`
home_dir=`dirname $ABSOLUTE_FILENAME`

cd "$ABSOLUTE_FILENAME"

sudo yum install yum-utils -y
sudo yum groupinstall development -y

sudo yum install https://centos7.iuscommunity.org/ius-release.rpm -y
wait
sudo yum install python36u python36u-pip python36u-devel -y


echo -e '\n Test \n'

sleep 2

if [[ `python3.6 -V | grep 'Python 3.6'` ]];then
    echo 'python3.6 installed'
else
    echo 'aborting, python3.6 in not installed'
    exit 1
fi

cd ../../

python3.6 -m venv venv
wait

pip install --upgrade pip

. venv/bin/activate
pip install -r ./server/requirements.txt