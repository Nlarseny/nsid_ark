#!/bin/sh

# stop unbound
systemctl stop unbound

# start bind
service named start