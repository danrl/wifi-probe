#!/bin/sh -x

IFACE=wlan0

airmon-ng check kill
rfkill unblock all
airmon-ng start ${IFACE}
ip link set up dev ${IFACE}mon

./wifi-scan.py ${IFACE}mon
