#!/usr/bin/env bash

ROUTE_TABLE=100

function exec_cmd() {
    cmd=${@:1:${#}}
    $cmd
    ret=$?
    if [ $ret -ne 0 ]; then
        >&2 echo "failed to exec command \"$cmd\""
        exit $ret
    fi
}

function init() {
    ip link set net1 up
    ip link set dev net1 arp off

    if [ $(ip rule show iif net1 | wc -l) -eq 0 ]; then
        exec_cmd "ip rule add iif net1 table $ROUTE_TABLE"
    fi
    if [ $(ip rule show iif eth0 | wc -l) -eq 0 ]; then
        exec_cmd "ip rule add iif eth0 table $ROUTE_TABLE"
    fi
}

function add_eip() {
    for rule in $@
    do
        arr=(${rule//,/ })
        eip=${arr[0]}
        # eip is expected as address/prefix (e.g. 1.2.3.4/32 or 2001:db8::1/128)
        eip_without_prefix=${eip%%/*}
        gateway=${arr[1]}

        # detect IPv6 by presence of ':' in the address
        if [[ "$eip_without_prefix" == *":"* ]]; then
            # IPv6
            exec_cmd "ip -6 addr replace $eip dev net1"
            exec_cmd "ip -6 route replace $eip dev net1 table $ROUTE_TABLE"
            exec_cmd "ip -6 route replace default via $gateway dev net1 table $ROUTE_TABLE"

            # Try to populate neighbor cache: prefer ndisc6 if available, else ping
            if command -v ndisc6 >/dev/null 2>&1; then
                # ndisc6 <target> <gw>
                exec_cmd "ndisc6 -q -r $eip_without_prefix $gateway"
            else
                # Use ping6 to trigger neighbor discovery
                exec_cmd "ping -6 -c 3 -I net1 $gateway >/dev/null 2>&1 || true"
            fi
        else
            # IPv4
            exec_cmd "ip addr replace $eip dev net1"
            # Use the same CIDR when adding a route to the table
            exec_cmd "ip route replace $eip dev net1 table $ROUTE_TABLE"
            exec_cmd "ip route replace default via $gateway dev net1 table $ROUTE_TABLE"
            ip link set dev net1 arp on
            exec_cmd "arping -f -c 3 -s $eip_without_prefix $gateway"
        fi
    done
}

function add_dnat() {
    for rule in $@
    do
        arr=(${rule//,/ })
        eip=(${arr[0]//\// })
        dport=${arr[1]}
        protocol=${arr[2]}
        internalIp=${arr[3]}
        internalPort=${arr[4]}
        defaultGateway=${arr[5]}
        # choose iptables vs ip6tables based on eip/internalIp
        if [[ "$eip" == *":"* || "$internalIp" == *":"* ]]; then
            IPT_CMD="ip6tables"
            IPT_SAVE_CMD="ip6tables-save"
        else
            IPT_CMD="iptables"
            IPT_SAVE_CMD="iptables-save"
        fi

        # check if rule already exists
        if $IPT_SAVE_CMD | grep "PREROUTING" | grep "-d $eip" | grep "p $protocol" | grep "dport $dport" | grep "destination $internalIp:$internalPort" > /dev/null 2>&1; then
            continue
        fi

        exec_cmd "$IPT_CMD -t nat -A PREROUTING -p $protocol -d $eip --dport $dport -j DNAT --to-destination $internalIp:$internalPort"

        # Add policy routing for internal IP via gateway (use ip or ip -6)
        if [[ "$internalIp" == *":"* ]]; then
            exec_cmd "ip -6 route replace $internalIp via $defaultGateway table $ROUTE_TABLE"
        else
            exec_cmd "ip route replace $internalIp via $defaultGateway table $ROUTE_TABLE"
        fi

        # ensure MASQUERADE for return path
        if $IPT_SAVE_CMD | grep "POSTROUTING" | grep "-d $internalIp" | grep "MASQUERADE" > /dev/null 2>&1; then
            :
        else
            exec_cmd "$IPT_CMD -t nat -I POSTROUTING -d $internalIp -j MASQUERADE"
        fi
    done
}

function del_dnat() {
    for rule in $@
    do
        arr=(${rule//,/ })
        eip=(${arr[0]//\// })
        dport=${arr[1]}
        protocol=${arr[2]}
        internalIp=${arr[3]}
        internalPort=${arr[4]}
        # pick iptables family
        if [[ "$eip" == *":"* || "$internalIp" == *":"* ]]; then
            IPT_CMD="ip6tables"
        else
            IPT_CMD="iptables"
        fi

        checkRule="-d $eip -p $protocol --dport $dport -j DNAT --to-destination $internalIp:$internalPort"
        if $IPT_CMD -t nat -C PREROUTING $checkRule > /dev/null 2>&1; then
            exec_cmd "$IPT_CMD -t nat -D PREROUTING -d $eip -p $protocol --dport $dport -j DNAT --to-destination $internalIp:$internalPort"
        fi
    done
}

rules=${@:2:${#}}
opt=$1
case $opt in
    init)
        echo "init $rules"
        init $rules
        ;;
    eip-add)
        echo "eip-add $rules"
        add_eip $rules
        ;;
    dnat-add)
        echo "dnat-add $rules"
        add_dnat $rules
        ;;
    dnat-del)
        echo "dnat-del rules"
        del_dnat $rules
        ;;
    *)
        echo "Usage: $0 [init|eip-add|dnat-add|dnat-del] ..."
        exit 1
        ;;
esac
