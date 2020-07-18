# Fake USG3

This example converts an EdgeRouter 4 into a fake USG3p by reading the data off EdgeRouter
and reformatting it into a stream of packets for the inform protocol.

Can be used as a reference for building other fake Unifi devices which partially or fully
ineteroperate with Unifi controllers.

 * Controller needs to have the networks defined.
 * eth0 = WAN
 * eth1 = LAN(s)

Supports traditional EdgeRouters, ERx and switch based units should be ready shortly as
interfaces need to be remapped.  EdgeRouters with WAN and LAN on different ports may not
work as intended as well.

**NOTE: ALPHA CODE**
