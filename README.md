# EchoDNS

A simple DNS server that returns IP addresses on demand.

## Why?

For testing? Or if you ever find some very bad network access controls that rely on resolving an hostname using dns.

## Examples

```
$ nslookup 127-0-0-1.echodns.werebug.com 192.168.1.193
Server:		192.168.1.193
Address:	192.168.1.193#53

Name:	127-0-0-1.echodns.werebug.com
Address: 127.0.0.1
Name:	127-0-0-1.echodns.werebug.com
Address: 127.0.0.1

$ nslookup 0a0a3520.echodns.werebug.com 192.168.1.193
Server:		192.168.1.193
Address:	192.168.1.193#53

Name:	0a0a3520.echodns.werebug.com
Address: 10.10.53.32
Name:	0a0a3520.echodns.werebug.com
Address: 10.10.53.32
```