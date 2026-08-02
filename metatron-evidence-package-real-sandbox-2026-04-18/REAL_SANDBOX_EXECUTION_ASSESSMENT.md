# Real Sandbox Execution Assessment

- Bundle date: 2026-04-18
- Verified real sandbox execution run files: 222
- Verified real sandbox execution techniques: 222
- Evidence bundle tier breakdown: {"bronze": 0, "gold": 222, "none": 0, "platinum": 0, "silver": 0}
- Coverage summary source count: 222
- Remaining not validated by the Linux sandbox sweep: 218
- Notes: this package contains only the corrected real-execution-backed sandbox evidence set and the supporting code/docs used to produce it.

Post-bundle follow-up checks performed on 2026-04-18:
- Snapshot integrity: the 222 verified-technique count above remains the authoritative bundle snapshot and was not modified by the follow-up checks below.
- T1095 follow-up: an isolated Linux namespace lab was created with `t1095srv` and `t1095cli` connected over a veth pair (`10.200.1.1/24` and `10.200.1.2/24`). Running `icmp-cnc` against `icmpdoor` produced repeated `shell:` prompts on the controller side, which is sufficient to show ICMP shell establishment in the lab. Command-output capture for `whoami` and `uname -s` remained partial, so this follow-up should be described as shell-establishment proof rather than a fully captured transcript.
- T1176 follow-up: Google Chrome on Linux explicitly ignored `--load-extension`, so follow-up validation moved to Firefox ESR using WebDriver temporary add-on installation from `atomic-red-team/atomics/T1176/src`. Firefox returned a temporary add-on identifier and recorded temporary-extension UUID state in the profile, confirming Linux add-on registration. Content-script execution on the proof page was not conclusively observed, so T1176 remains short of full real-execution proof.

Included contents:
- atomic_runs/: filtered real execution run JSONs only
- evidence_bundle/: regenerated TVRs and summary for the 222 verified techniques
- backend/: evidence scoring and runner code
- scripts/: sweep, bundle, and VM import/setup helpers
- docs/: runner and Windows VM documentation
- config/: example runner and VM config

Technique list:
T1001.002, T1003.007, T1003.008, T1005, T1007, T1014, T1016, T1016.001, T1018, T1027, T1027.001, T1027.002, T1027.004, T1027.013, T1030, T1033, T1036.003, T1036.004, T1036.005, T1036.006, T1037.004, T1040, T1046, T1048, T1048.002, T1048.003, T1049, T1053.002, T1053.003, T1053.006, T1053.007, T1055.008, T1056.001, T1057, T1059.004, T1059.006, T1068, T1069.001, T1069.002, T1070.002, T1070.003, T1070.004, T1070.006, T1070.008, T1071.001, T1074.001, T1078, T1078.002, T1078.003, T1078.004, T1080, T1081, T1082, T1083, T1087.001, T1087.002, T1090.001, T1090.003, T1098, T1098.001, T1098.002, T1098.003, T1098.004, T1102, T1105, T1110.001, T1110.003, T1110.004, T1113, T1114.002, T1114.003, T1115, T1124, T1132.001, T1135, T1136.001, T1136.002, T1136.003, T1140, T1185, T1189, T1190, T1195.002, T1199, T1200, T1201, T1203, T1205, T1210, T1217, T1222.002, T1234, T1234.001, T1398, T1439, T1444, T1465, T1484.002, T1485, T1486, T1489, T1491, T1491.002, T1495, T1496, T1497.001, T1497.003, T1518.001, T1526, T1528, T1529, T1530, T1531, T1533, T1534, T1537, T1538, T1542, T1542.002, T1542.003, T1543.002, T1546.004, T1546.005, T1546.018, T1547.006, T1548.001, T1548.003, T1552, T1552.001, T1552.003, T1552.004, T1552.005, T1552.007, T1553, T1553.002, T1553.004, T1554, T1555.003, T1555.006, T1556, T1556.001, T1556.003, T1556.006, T1557, T1557.002, T1559.001, T1560.001, T1560.002, T1561, T1562, T1562.001, T1562.003, T1562.004, T1562.006, T1562.008, T1562.010, T1562.012, T1564.001, T1564.008, T1565, T1565.001, T1567.002, T1568, T1569.002, T1571, T1572, T1574, T1574.002, T1574.006, T1578.001, T1580, T1583, T1587, T1588, T1589, T1589.001, T1590, T1590.001, T1590.002, T1590.004, T1592, T1592.002, T1595, T1595.001, T1595.003, T1596, T1598, T1598.003, T1601, T1601.001, T1606.002, T1609, T1610, T1611, T1612, T1613, T1614, T1614.001, T1619, T1626, T1629, T1633, T1648, T1651, T1652, T1656, T1657, T1658, T1659, T1660, T1661, T1665, T1669, T1670, T4541, T5305, T5328, T5466, T5993, T7527, T8005, T9787
