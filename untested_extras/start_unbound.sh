#!/bin/sh

# stop bind
service named stop

# start unbound
systemctl start unbound