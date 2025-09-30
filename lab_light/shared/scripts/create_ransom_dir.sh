#!/bin/sh
set -e

mkdir -p /tmp/ransom
#chown -R monkey:monkey /tmp/ransom
chmod 0777 /tmp/ransom

printf 'Super secret data\n' > /tmp/ransom/secret.txt
printf 'Another super secret\n' > /tmp/ransom/other_secret.txt
#chown monkey:monkey /tmp/ransom/*
chmod 0666 /tmp/ransom/*

