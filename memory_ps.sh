#!/bin/bash
# Logga memoria processo + memoria container ogni 0.5s
# Uso:
#   ./log_mem_combo.sh classic
#   ./log_mem_combo.sh pq1
#   ./log_mem_combo.sh hybrid2
# ecc.

CONTAINER="test-zk_mem"
OUTFILE="mem_combo_log.csv"
INTERVAL="0.5"                 # Secondi

# Se il CSV non esiste aggiungi header
if [ ! -f "$OUTFILE" ]; then
    echo "timestamp,rss_kb,vsz_kb,cgroup_current_bytes,cgroup_peak_bytes" \
        > "$OUTFILE"
fi

# Ottieni il PID reale del processo del container
PID=$(podman inspect -f '{{.State.Pid}}' "$CONTAINER")

if [ -z "$PID" ]; then
    echo "Errore: impossibile ottenere PID per container $CONTAINER"
    exit 1
fi

echo "[*] Container: $CONTAINER  (PID host = $PID)"
echo "[*] Logging ogni $INTERVAL s'"
echo "[*] Output → $OUTFILE"
echo "[CTRL+C per interrompere]"

while true; do
    TS=$(date +%s.%3N)

    # ps sull'host (funziona sempre)
    RSS=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ')
    VSZ=$(ps -o vsz= -p "$PID" 2>/dev/null | tr -d ' ')

    # Se ps non trova il processo, lascia valori vuoti
    if [ -z "$RSS" ]; then RSS=""; fi
    if [ -z "$VSZ" ]; then VSZ=""; fi

    # Leggi cgroup dall'interno del container (senza sudo)
    CG_CUR=$(podman exec "$CONTAINER" sh -c 'cat /sys/fs/cgroup/memory.current 2>/dev/null')
    CG_PEAK=$(podman exec "$CONTAINER" sh -c 'cat /sys/fs/cgroup/memory.peak 2>/dev/null')

    echo "$TS,$RSS,$VSZ,$CG_CUR,$CG_PEAK" >> "$OUTFILE"

    sleep "$INTERVAL"
done
