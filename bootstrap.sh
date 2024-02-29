#!/bin/bash

########
#
# script that will be ran by flask
#
########

apt-get update
pip install flask scapy
sudo python app.py
python app.py
