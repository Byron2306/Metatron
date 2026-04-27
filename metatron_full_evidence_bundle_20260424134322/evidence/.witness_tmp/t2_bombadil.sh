#!/bin/bash
echo '══════════════════════════════════════'
echo '  BOMBADIL — THE LAW DAEMON'
echo '══════════════════════════════════════'
echo ''
cd '/home/byron/Integritas-Mechanicus-clean/Integritas-Mechanicus'
python3 '/home/byron/Integritas-Mechanicus-clean/Integritas-Mechanicus/arda_os/backend/services/arda_bombadil.py'
echo ''
read -p '  Press Enter to close...'
