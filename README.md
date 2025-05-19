# TinyRadius 1.2

TinyRadius is a small, fast and reliable Java Radius library capable of sending and receiving Radius packets as specified by RFC 2865/2866.
TinyRadius is not a fully-fledged Radius server, but helps you to implement Radius services in your application.

Based on https://tinyradius.sourceforge.net/.

Supports these features:

- PAP, CHAP, MSCHAPv1, MSCHAPv2 authentication for client and server usage.
- RADSEC protocol for client and server usage.
- DisconnectPackage (Tested against Mikrotik router)

Tested as a RADIUS server for Mikrotik router (users authenticate and accounting).
