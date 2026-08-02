# VNS/VPN Traffic Check - AAB rev13

Scope: VNS service, backend VNS/VPN logs, and WireGuard container traffic during the AAB run hour.

## Verdict

No VNS/VPN traffic corroboration was found for the rev13 AAB run. WireGuard was up and had configured peers, but `wg0` showed zero RX/TX packets and no handshakes/traffic counters. The WireGuard container emitted no Docker log lines during the AAB hour. Backend logs did not show VNS/VPN activity in the same window, and `/api/advanced/vns/*` plus `/api/vpn/status` are auth-gated.

This is expected for the rev13 run because the AAB runner used internal TestClient/local process mode, not a VNS-visible network path.

## Observations

- WireGuard log lines in window: 0
- Configured WireGuard peers: 10
- `wg0` zero RX/TX: True
- VNS API probe: `/api/advanced/vns/stats` and `/api/advanced/vns/flows` returned `403 Not authenticated`.
- VPN API probe: `/api/vpn/status` returned `403 Authentication required`.

## WireGuard Status Snapshot

```text
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    RX:  bytes packets errors dropped  missed   mcast           
      75885588 1017232      0       0       0       0 
    TX:  bytes packets errors dropped carrier collsns           
      75885588 1017232      0       0       0       0 
3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/none 
    RX:  bytes packets errors dropped  missed   mcast           
             0       0      0       0       0       0 
    TX:  bytes packets errors dropped carrier collsns           
             0       0      0       0       0       0 
181: eth0@if182: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default 
    link/ether 02:42:ac:1c:00:0d brd ff:ff:ff:ff:ff:ff link-netnsid 0
    RX:  bytes packets errors dropped  missed   mcast           
         27162     233      0       0       0       0 
    TX:  bytes packets errors dropped carrier collsns           
           182       3      0       0       0       0 
interface: wg0
  public key: DDCX+EV1SAWRuyY6DOACg4WFtJ3u8TdEQiqpesGlEl4=
  private key: (hidden)
  listening port: 51820

peer: iHglCnwkObQTY4STx7C1Uk0satfBAAFrj7OGpxP47WY=
  preshared key: (hidden)
  allowed ips: 10.200.200.2/32

peer: G52j7p5btadM1OgSVsEN+0LLkvpOYC8Q0d3CSu8FAlw=
  preshared key: (hidden)
  allowed ips: 10.200.200.3/32

peer: t4kYLBW2vlkw1ZOvNQEcdKvUhgZ1mYZQ5cK/YMwS9So=
  preshared key: (hidden)
  allowed ips: 10.200.200.4/32

peer: wvGFLWyQnyAbKdQjL2l3Gt+IrKHYmvJ0z8I44OH3WwI=
  preshared key: (hidden)
  allowed ips: 10.200.200.5/32

peer: zuLsFyHQgEBjZEl4nShYdSk8lAJdgmTlztCcqkDwJik=
  preshared key: (hidden)
  allowed ips: 10.200.200.6/32

peer: m7ddyNAR1bw2hdr5/BDJrw5OfQ7mqTFd5SVf8wnMbAI=
  preshared key: (hidden)
  allowed ips: 10.200.200.7/32

peer: w8asd3XxggaE446FXU6iPfjrq5EwtrAdufcMfy2MeXs=
  preshared key: (hidden)
  allowed ips: 10.200.200.8/32

peer: raEqGlhnlxTFlkdQRGf4tWk4Jlw8PUbHBeurtJ8PKx8=
  preshared key: (hidden)
  allowed ips: 10.200.200.9/32

peer: 4aobsBCJJlpZqtoM2W0HboiwHYc2uBeYwSF/E+AlsE8=
  preshared key: (hidden)
  allowed ips: 10.200.200.10/32

peer: V8vxrhNtgsUIw8N+StxPMwA241UoyWRo0kvxiutua2g=
  preshared key: (hidden)
  allowed ips: 10.200.200.11/32
```

## VNS/VPN API Probe

```text
URL http://127.0.0.1:8001/api/advanced/vns/stats
HTTP/1.1 403 Forbidden
date: Mon, 11 May 2026 17:47:50 GMT
server: uvicorn
content-length: 30
content-type: application/json

{"detail":"Not authenticated"}URL http://127.0.0.1:8001/api/advanced/vns/flows
HTTP/1.1 403 Forbidden
date: Mon, 11 May 2026 17:47:50 GMT
server: uvicorn
content-length: 30
content-type: application/json

{"detail":"Not authenticated"}URL http://127.0.0.1:8001/api/vpn/status
HTTP/1.1 403 Forbidden
date: Mon, 11 May 2026 17:47:50 GMT
server: uvicorn
content-length: 36
content-type: application/json

{"detail":"Authentication required"}
```
