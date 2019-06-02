# LAN2json

This module provides a class with 2 static methods:
  `portscan`: finds TCP ports that have bound listeners on a specific host
  `scan`: requires root privilege and finds IPv4 and MAC addresses on a LAN

See the [LAN2json documentation](https://megamosquito.github.io/LAN2json/LAN2json.html) for more info.

Note that the `scan` function requires `nmap` to be installed.

Note also that `scan` does not require this, but the `portscan` function
requires [rfc1340](https://github.com/MegaMosquito/rfc1340).  So if you wish
to use the `portscan` function, run this command in this directory:

```
  git clone https://github.com/MegaMosquito/rfc1340.git
```

Written by Glen Darling, December 2018.
