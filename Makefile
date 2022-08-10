vm1:
    route add default gw 192.168.130.158

vm2:
    echo 0 > /proc/sys/net/ipv4/ip_forward
    iptables -t nat -A POSTROUTING -o enp1s0 -j MASQUERADE
    iptables -t nat -A POSTROUTING -o enp6s0 -j MASQUERADE

vm3:
    echo 1 > /proc/sys/net/ipv4/ip_forward
    ip route add 192.168.130.0/24 via 192.168.140.181
    iptables -t nat -A POSTROUTING -o enp1s0 -j MASQUERADE