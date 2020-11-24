#!/bin/bash

device="wlx9cefd5febf89"
server_ip="192.168.0.1"
attacker_ip="192.168.0.116"
victim_ip="192.168.0.98"


sudo ./main ${device} ${server_ip} ${attacker_ip} ${victim_ip}
