#! /bin/bash
# 
# This script uses Netem (http://www.linux-foundation.org/en/Net:Netem) to simulate 
# lag and packet loss on traffic going and coming from a selected network.
#
# Customize value at start of script.
#
# Copyright (C) 2008 INL
# Written by Éric Leblond <eric@inl.fr>
#            Vincent Deffontaines <vincent@inl.fr>
# INL http://www.inl.fr/
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.


IFACE="ham0 tun0" # Input and output interface to simulate lag in INPUT and OUTPUT
TARGET="10.0.0.1/24" # Hosts or networks to apply lag on
NO_SSH_DELAY="yes" # if set to "yes" ssh will not be impacted by delay

# Default value
DELAY="3000"  # delay in ms
VAR="2000"  # delay in ms (packets will be delayed from DELAY +/- VAR)
BANDWITH="200kbit" # bp of simulated link
PERCENTLOSS="2%" # Percent of packet loss

# Path to commands
IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables
TC=/sbin/tc

########################################
# No need to modify under this line.
########################################

if [ -n "$2" ]; then
  DELAY=$2
  echo "DELAY : $DELAY ms"
fi

if [ -n "$3" ]; then
  PERCENTLOSS="$3%"
  echo "LOSS : $PERCENTLOSS"
fi


do_start() {

modprobe sch_prio
modprobe sch_netem

for IIF in ${IFACE}; do
${TC} qdisc add dev ${IIF} root handle 1: prio bands 3
${TC} qdisc add dev ${IIF} parent 1:3 handle 30: netem \
  delay ${DELAY}ms ${VAR}ms loss ${PERCENTLOSS} 33.33%
 
${TC} qdisc add dev ${IIF} parent 30:1 tbf rate ${BANDWITH} buffer 1600 limit 3000

${TC} filter add dev ${IIF} protocol ip parent 1:0 prio 3 handle 5000 fw flowid 1:3
${TC} filter add dev ${IIF} protocol ipv6 parent 1:0 prio 4 handle 5000 fw flowid 1:3

done;

for NET in ${TARGET}; do
  if [[ ${NET} == *:* ]]; then
      IPT=${IP6TABLES}
  else
      IPT=${IPTABLES}
  fi
  ${IPT} -A POSTROUTING -t mangle -d ${NET} -j MARK --set-mark 5000
  ${IPT} -A POSTROUTING -t mangle -s ${NET} -j MARK --set-mark 5000
  if [ ${NO_SSH_DELAY} = "yes" ]; then
    ${IPT} -A POSTROUTING -t mangle -d ${NET} -p tcp --dport 22 -j MARK --set-mark 0
    ${IPT} -A POSTROUTING -t mangle -s ${NET} -p tcp --sport 22 -j MARK --set-mark 0
  fi
done;

}

do_stop() {

for IIF in ${IFACE}; do
  ${TC} qdisc del dev ${IIF} root
done;

for NET in ${TARGET}; do
  if [[ ${NET} == *:* ]]; then
      IPT=${IP6TABLES}
  else
      IPT=${IPTABLES}
  fi
  ${IPT} -D POSTROUTING -t mangle -d ${NET} -j MARK --set-mark 5000
  ${IPT} -D POSTROUTING -t mangle -s ${NET} -j MARK --set-mark 5000
  if [ ${NO_SSH_DELAY} = "yes" ]; then
    ${IPT} -D POSTROUTING -t mangle -d ${NET} -p tcp --dport 22 -j MARK --set-mark 0
    ${IPT} -D POSTROUTING -t mangle -s ${NET} -p tcp --sport 22 -j MARK --set-mark 0
  fi
done;

  rmmod sch_prio
  rmmod sch_netem
  
}

do_status() {

for IIF in ${IFACE}; do
  ${TC} qdisc show dev ${IIF}
  ${TC} filter show dev ${IIF}
done;

  ${IPTABLES} -L POSTROUTING -nv -t mangle

}

case "$1" in
  start)
    do_start
    ;;
  stop)
    do_stop
    ;;
  restart)
    do_stop
    do_start
    ;;
  status)
    do_status
    ;;
  *)
    echo "Usage : lagfactory.sh start|stop [ \$DELAY [ \$LOSS ] ]"
    echo "  DELAY in ms, LOSS in %"
    ;;
esac
