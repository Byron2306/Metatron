#!/bin/bash
echo '══════════════════════════════════════'
echo '  SCREEN RECORDER — WITNESS RUN'
echo '  Press q to stop recording'
echo '══════════════════════════════════════'
echo ''
sleep 2
ffmpeg -f x11grab -framerate 30 -video_size 1920x1080 -i :0.0 \
    -f pulse -i alsa_output.pci-0000_00_1f.3-platform-skl_hda_dsp_generic.HiFi__Speaker__sink.monitor \
    -f pulse -i alsa_input.pci-0000_00_1f.3-platform-skl_hda_dsp_generic.HiFi__Mic1__source \
    -filter_complex '[1:a][2:a]amix=inputs=2:duration=first[aout]' \
    -map 0:v -map '[aout]' \
    -c:v libx264 -preset fast -crf 23 \
    -c:a aac -b:a 192k \
    /home/byron/Integritas-Mechanicus-clean/Integritas-Mechanicus/evidence/FIRST_ETHICAL_PROOF_WITNESS_RUN.mp4
echo ''
echo '  Recording saved.'
read -p '  Press Enter to close...'
