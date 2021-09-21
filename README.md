# LAN2json

This module provides a class with 2 static methods:

 * `portscan`: finds TCP ports that have bound listeners on a specific host
 * `scan`: finds IPv4 and MAC addresses for all the hosts on your LAN

See the [LAN2json documentation](https://megamosquito.github.io/LAN2json/LAN2json.html) for more info.

Note that the `scan` function requires `nmap` to be installed.

Note also that it is best to run the `scan` function as a normal user with "passowrdless" sudo access to use `nmap`. If you don't want to bother configuring that then it **must run as root**. Why? When `nmap` is run as a non-root user, its output format is different and the most important bit of information -- the MAC addresses of the hosts -- is simply not provided. So the `scan` function will fail in that case.

Note also that the `portscan` function requires [rfc1340](https://github.com/MegaMosquito/rfc1340), but the `scan` does not require it.  So only if you wish
to use the `portscan` function, also run this command in this directory to pull in the RFC1340 port number info:

```
  git clone https://github.com/MegaMosquito/rfc1340.git
```

Written by Glen Darling (mosquito@darlingevil.com), December 2018.

