# Network Sensor Container Check - AAB rev13

Scope: Suricata and Zeek containers around the AAB run window on 2026-05-11.

## Verdict

Suricata was active and logging during the AAB window, but the traffic it saw was not the AAB closed-loop TestClient traffic. The hour is dominated by Kibana to Elasticsearch, Arkime telemetry, and a small amount of frontend/backend/ngrok UI activity. Zeek was not actively capturing: its container process is `tail -f /dev/null` and its logs stop before the AAB run window.

This does not weaken the AAB JSON evidence, but it means Suricata/Zeek cannot be claimed as packet-level corroboration for this particular run. For that, rerun AAB with `--networked` or `--url http://127.0.0.1:<port>` against a container-visible service path.

## Suricata 15:00 UTC Hour

- EVE events in hour: 26,384
- EVE log size: 4,942,116,552 bytes
- Event types: fileinfo=11893, http=8357, alert=2606, anomaly=2600, stats=450, flow=315, dns=122, tls=39
- Top HTTP hosts: elasticsearch=12853, 127.0.0.1=154, devious-viability-linked.ngrok-free.dev=45
- Top HTTP agents: Kibana/8.11.0=12853, arkime=154, Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0=45
- Top alert: SURICATA HTTP unable to match response to request (2592)

## Container IP Map

```text
/seraph-arkime-capture 
/seraph-backend 172.28.0.3
/seraph-bloodhound 172.28.0.21
/seraph-bloodhound-postgres 172.28.0.20
/seraph-clamav 172.28.0.14
/seraph-cuckoo 172.28.0.17
/seraph-cuckoo-web 172.28.0.18
/seraph-elasticsearch 172.28.0.10
/seraph-falco 172.28.0.5
/seraph-fleet 172.28.0.15
/seraph-fleet-mysql 172.28.0.7
/seraph-fleet-redis 172.28.0.11
/seraph-frontend 172.28.0.4
/seraph-kibana 172.28.0.16
/seraph-mongodb 172.28.0.2
/seraph-neo4j 172.28.0.19
/seraph-osquery 172.28.0.12
/seraph-suricata 
/seraph-trivy 172.28.0.8
/seraph-unified-agent 
/seraph-velociraptor 172.28.0.9
/seraph-wireguard 172.28.0.13
/seraph-yara 172.28.0.6
/seraph-zeek
```

## Zeek Status

```text
total 14556
drwxr-xr-x    2 root     root          4096 May  2 06:45 .
drwxr-xr-x    1 root     root          4096 May 10 13:32 ..
-rw-r--r--    1 root     root          2393 Apr 25 07:15 capture_loss.log
-rw-r--r--    1 root     root         10158 May 10 13:21 conn.log
-rw-r--r--    1 root     root           537 Apr 17 17:05 dhcp.log
-rw-r--r--    1 root     root          2346 May 10 13:21 dns.log
-rw-r--r--    1 root     root          1287 May  2 09:11 dpd.log
-rw-r--r--    1 root     root          6535 May 10 13:21 files.log
-rw-r--r--    1 root     root         29354 May 10 13:21 http.log
-rw-r--r--    1 root     root         32051 Apr 24 21:29 loaded_scripts.log
-rw-r--r--    1 root     root      14745912 May  2 10:53 mysql.log
-rw-r--r--    1 root     root          1010 Apr 28 09:56 notice.log
-rw-r--r--    1 root     root           227 May 10 13:21 packet_filter.log
-rw-r--r--    1 root     root           380 May  1 09:07 reporter.log
-rw-r--r--    1 root     root           918 May 10 13:21 ssl.log
-rw-r--r--    1 root     root         14648 Apr 25 07:14 stats.log
-rw-r--r--    1 root     root           472 May 10 13:21 weird.log
-rw-r--r--    1 root     root          2535 May  1 19:54 x509.log
PID   USER     TIME  COMMAND
    1 root      0:05 tail -f /dev/null
   62 root      0:00 sh -lc ls -la /usr/local/zeek/logs; ps aux 2>/dev/null | head -20
   71 root      0:00 ps aux
   72 root      0:00 head -20
```
