#!/bin/bash
# Keep the traffic of the tunnel server itself out of the tunnel.
#
# This is only needed when the server runs on the same machine as the TUN
# client, which is the case in the test setup.  Everything the server sends
# has the address of the machine as its source, and those packets are sent
# through a table of their own.  The table needs the local network AND the
# gateway, otherwise the replies of the machine itself get lost.
#
# Usage: sudo ti-routes.sh [device]
DEV=${1:-ens192}

LAN_IP=""
GATEWAY=""
SUBNET=""
for i in $(seq 1 60); do
  LAN_IP=$(ip -4 -o addr show "$DEV" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  SUBNET=$(ip -4 -o addr show "$DEV" 2>/dev/null | awk '{print $4}' | cut -d/ -f2)
  GATEWAY=$(ip route show default 2>/dev/null | awk '{print $3}' | head -1)
  if [ -n "$LAN_IP" ] && [ -n "$GATEWAY" ] && [ -n "$SUBNET" ]; then
    break
  fi
  sleep 2
done

if [ -z "$LAN_IP" ] || [ -z "$GATEWAY" ]; then
  echo "the network is not ready yet" >&2
  exit 1
fi

# the network address, a host address is not a valid prefix
NET=$(echo "$LAN_IP" | awk -F. '{printf "%s.%s.%s.0", $1, $2, $3}')

grep -q "^100 lanroute" /etc/iproute2/rt_tables 2>/dev/null || echo "100 lanroute" >> /etc/iproute2/rt_tables

# first take the broken rule away, then build the table, then put the rule
# back.  In that order the machine is never left with a rule that points at
# an empty table.
ip rule del pref 100 2>/dev/null
ip route flush table lanroute 2>/dev/null
ip route replace "$NET"/"$SUBNET" dev "$DEV" scope link table lanroute || exit 1
ip route replace default via "$GATEWAY" dev "$DEV" table lanroute || exit 1
ip rule add pref 100 from "$LAN_IP"/32 lookup lanroute
echo "ti-routes: lan=$NET/$SUBNET gateway=$GATEWAY"
