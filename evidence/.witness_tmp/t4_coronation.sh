#!/bin/bash
echo '══════════════════════════════════════════════════════════'
echo '  THE FIRST ENCOUNTER — CORONATION CEREMONY'
echo '  Transcript → /home/byron/Integritas-Mechanicus-clean/Integritas-Mechanicus/evidence/FIRST_ETHICAL_PROOF_CORONATION.txt'
echo '══════════════════════════════════════════════════════════'
echo ''
sleep 2
cd '/home/byron/Integritas-Mechanicus-clean/Integritas-Mechanicus'
script -a '/home/byron/Integritas-Mechanicus-clean/Integritas-Mechanicus/evidence/FIRST_ETHICAL_PROOF_CORONATION.txt' -c 'python3 /home/byron/Integritas-Mechanicus-clean/Integritas-Mechanicus/arda_os/backend/services/coronation_cli.py'
echo ''
echo '  Transcript saved.'
read -p '  Press Enter to close...'
