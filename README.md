# beacon
Localize network failures using IP in IP encapsulation

### Motivation
IP in IP encapsulation is a protocol described in [RFC 2003](https://tools.ietf.org/html/rfc2003) as:
> a method by which an IP datagram may be encapsulated (carried as payload) within an IP datagram. Encapsulation is suggested as a means to alter the normal IP routing for datagrams, by delivering them to an intermediate destination that would otherwise not be selected by the (network part of the) IP Destination Address field in the original IP header.

The intermediate destinations (or hops) a given packet will take is decided by the network topology and the routing protocols deployed on the nodes therein, and standard network diagnostic tooling such as [traceroute](https://en.wikipedia.org/wiki/Traceroute) and [mtr](https://en.wikipedia.org/wiki/MTR_(software)) are subject to this constraint. By recursively encapsulating packets, one can specify the exact sequence of hops a packet should take through the network thus providing an accurate measurement of loss over a specific network path.

### Installation
```
$ go get -u github.com/trstruth/beacon
$ go install $GOPATH/src/github.com/trstruth/beacon/braceroute
$ sudo setcap cap_net_admin+eip $GOPATH/bin/braceroute # grant cap_net_admin to binary, see constraints
$ braceroute --help # confirm installation
```

### Usage
```
$ braceroute icr01.par30
Doing traceroute to icr01.par30.ntwk.msn.net. (207.46.33.149)
10.20.30.67
10.22.25.198
ae24-0.icr03.mwh01.ntwk.msn.net. (104.44.227.108)
be-161-0.ibr02.mwh01.ntwk.msn.net. (104.44.21.153)
be-7-0.ibr02.cys04.ntwk.msn.net. (104.44.18.224)
be-8-0.ibr02.dsm05.ntwk.msn.net. (104.44.18.151)
be-4-0.ibr02.ch2.ntwk.msn.net. (104.44.19.252)
be-1-0.ibr02.ch4.ntwk.msn.net. (104.44.7.223)
be-3-0.ibr02.cle30.ntwk.msn.net. (104.44.7.117)
be-2-0.ibr02.ewr30.ntwk.msn.net. (104.44.7.99)
be-3-0.ibr02.nyc30.ntwk.msn.net. (104.44.7.104)
be-7-0.ibr02.lon22.ntwk.msn.net. (104.44.18.155)
be-6-0.ibr02.par30.ntwk.msn.net. (104.44.17.78)
icr01.par30.ntwk.msn.net. (207.46.33.149)
```

```
$ # reverse traceroute - note the path is not symmetrical to the path above
$ braceroute -r icr01.par30
Doing reverse traceroute from icr01.par30.ntwk.msn.net. (207.46.33.149)
icr01.par30.ntwk.msn.net. (207.46.33.149)
be-120-0.ibr02.par30.ntwk.msn.net. (104.44.11.237)
be-6-0.ibr02.lon22.ntwk.msn.net. (104.44.17.79)
be-7-0.ibr02.nyc30.ntwk.msn.net. (104.44.18.154)
be-3-0.ibr02.ewr30.ntwk.msn.net. (104.44.7.105)
be-2-0.ibr02.cle30.ntwk.msn.net. (104.44.7.98)
be-3-0.ibr02.ch4.ntwk.msn.net. (104.44.7.116)
be-1-0.ibr02.ch2.ntwk.msn.net. (104.44.7.222)
be-4-0.ibr02.dsm05.ntwk.msn.net. (104.44.19.253)
be-8-0.ibr02.cys04.ntwk.msn.net. (104.44.18.150)
be-7-0.ibr02.mwh01.ntwk.msn.net. (104.44.18.225)
ae162-0.icr02.mwh01.ntwk.msn.net. (104.44.21.150)
ae21-0.co1-96c-1b.ntwk.msn.net. (104.44.227.193)
nettools1-co1.phx.gbl. (10.20.30.96)

```

```
$ braceroute spray -s icr01.par30 -d ibr01.par30
Finding path from 207.46.33.149 to 25.125.46.50
[10.20.30.96 207.46.33.149 25.125.33.47 25.125.33.50 25.125.33.42 25.125.46.50]
207.46.33.149 -> 10.20.30.96
packet success rate: 1/1, loss: 0.000000%
timed out waiting for the packet
packet success rate: 1/2, loss: 50.000000%
...
```

### Constraints
- Permissions: because beacon requires the ability to create a raw socket, it must either be run as root or granted the [`cap_net_admin`](http://man7.org/linux/man-pages/man7/capabilities.7.html) capability
- Router support for IP in IP: IP in IP encapsulation has only seen widespread implementation in the last (?) years.  While we believe most of the internal Azure fleet supports the protocol, there may be limited support in the wild.
- VM support for IP in IP: Virtual machines may drop encapsulated traffic depending on their network configuration.  To circumvent this, we have run this tool on a baremetal machine.
