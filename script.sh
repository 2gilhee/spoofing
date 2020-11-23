#!/bin/bash

device="ens33"
server_ip="192.168.80.130"
attacker_ip="192.168.80.128"
victim_ip="192.168.80.129"


sudo ./main ${device} ${server_ip} ${attacker_ip} ${victim_ip}
