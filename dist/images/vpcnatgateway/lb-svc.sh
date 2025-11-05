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

# helper: detect if an address/string looks like IPv6
function is_ipv6() {
    addr="$1"
    # If it contains a ':' character it's IPv6 (simple heuristic)
    if [[ "$addr" == *":"* ]]; then
        return 0
    fi
    return 1
}

# wrapper to return correct iptables command (iptables vs ip6tables)
function iptables_for() {
    addr="$1"
    if is_ipv6 "$addr"; then
        echo "ip6tables"
    else
        echo "iptables"
    fi
}

function init() {
    ip link set net1 up
    # Disable ARP only for IPv4; IPv6 uses NDP
    ip link set dev net1 arp off || true

    # add both IPv4 and IPv6 rules if not present
    if [ $(ip rule show iif net1 | wc -l) -eq 0 ]; then
        exec_cmd "ip rule add iif net1 table $ROUTE_TABLE"
    fi
    if [ $(ip rule show iif eth0 | wc -l) -eq 0 ]; then
        exec_cmd "ip rule add iif eth0 table $ROUTE_TABLE"
    fi
    # IPv6 rules
    if ip -6 rule show iif net1 >/dev/null 2>&1; then
        if [ $(ip -6 rule show iif net1 | wc -l) -eq 0 ]; then
            exec_cmd "ip -6 rule add iif net1 table $ROUTE_TABLE"
        fi
        if [ $(ip -6 rule show iif eth0 | wc -l) -eq 0 ]; then
            exec_cmd "ip -6 rule add iif eth0 table $ROUTE_TABLE"
        fi
    fi
}

function add_eip() {
    for rule in $@
    do
        arr=(${rule//,/ })
        eip=${arr[0]}
        eip_without_prefix=(${eip//\// })
        gateway=${arr[1]}

        if is_ipv6 "$eip"; then
            eip_network=$(ipv6calc -n $eip 2>/dev/null | awk -F '=' '{print $2}')
            eip_prefix=$(ipv6calc -p $eip 2>/dev/null | awk -F '=' '{print $2}')

            exec_cmd "ip -6 addr replace $eip dev net1"
            exec_cmd "ip -6 route replace $eip_network/$eip_prefix dev net1 table $ROUTE_TABLE"
            exec_cmd "ip -6 route replace default via $gateway dev net1 table $ROUTE_TABLE"
            exec_cmd "ndisc6 -q -r -s $eip_without_prefix $gateway"
        else
            # IPv4 path (unchanged behavior)
            eip_network=$(ipcalc -n $eip | awk -F '=' '{print $2}')
            eip_prefix=$(ipcalc -p $eip | awk -F '=' '{print $2}')

            exec_cmd "ip addr replace $eip dev net1"
            exec_cmd "ip route replace $eip_network/$eip_prefix dev net1 table $ROUTE_TABLE"
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
        # Select ip/iptables variant based on eip or internalIp
        iptables_cmd=$(iptables_for "$eip")
        iptables_save_cmd="${iptables_cmd}-save"

        # check if already exist
        if $iptables_save_cmd 2>/dev/null | grep "PREROUTING" | grep "\-d $eip" | grep "p $protocol" | grep "dport $dport" | grep "destination $internalIp:$internalPort" >/dev/null 2>&1; then
            continue
        fi

        exec_cmd "$iptables_cmd -t nat -A PREROUTING -p $protocol -d $eip --dport $dport -j DNAT --to-destination $internalIp:$internalPort"

        # add route for internal IP in appropriate ip family
        if is_ipv6 "$internalIp"; then
            exec_cmd "ip -6 route replace $internalIp via $defaultGateway table $ROUTE_TABLE"
        else
            exec_cmd "ip route replace $internalIp via $defaultGateway table $ROUTE_TABLE"
        fi

        if $iptables_save_cmd 2>/dev/null | grep "POSTROUTING" | grep "\-d $internalIp" | grep "MASQUERADE" >/dev/null 2>&1; then
            continue
        fi
        exec_cmd "$iptables_cmd -t nat -I POSTROUTING -d $internalIp -j MASQUERADE"
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

        iptables_cmd=$(iptables_for "$eip")
        checkRule="-d $eip -p $protocol --dport $dport -j DNAT --to-destination $internalIp:$internalPort"
        if $iptables_cmd -t nat -C PREROUTING $checkRule > /dev/null 2>&1; then
            exec_cmd "$iptables_cmd -t nat -D PREROUTING -d $eip -p $protocol --dport $dport -j DNAT --to-destination $internalIp:$internalPort"
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
        echo "Usage: $0 [init|eip-add|dnat-add] ..."
        exit 1
        ;;
esac
