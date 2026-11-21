#!/bin/sh
# Sobe os dois sshd do laboratório dentro do contêiner (Alpine).
set -e
apk add --no-cache openssh-server >/dev/null
ssh-keygen -A
/usr/sbin/sshd -e -f /lab/ssh/sshd-hibrido.conf
exec /usr/sbin/sshd -D -e -f /lab/ssh/sshd-classico.conf
