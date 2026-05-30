#!/bin/bash
LOG="/var/log/ipdb_backup.log"
BACKUP_DIR="/opt/netquery/data/ipdb_backups"
DATE=$(date +"%Y-%m-%d_%H-%M")
FILE="$BACKUP_DIR/ipdb-backup-$DATE.xlsx"
mkdir -p "$BACKUP_DIR"
echo "[$(date)] Iniciando backup IPDB..." >> "$LOG"
python3 << PYEOF
import json, sys
from openpyxl import Workbook
from datetime import datetime

db = json.load(open('/opt/netquery/data/ipdb.json'))
wb = Workbook()
ws = wb.active
ws.title = 'IPdb'

if db:
    cols = [k for k in db[0].keys() if k != 'id']
    ws.append(cols)
    for row in db:
        ws.append([str(row.get(c,'')) for c in cols])

filename = '/opt/netquery/data/ipdb_backups/ipdb-backup-$(date +"%Y-%m-%d_%H-%M").xlsx'
wb.save(filename)

# Mantener max 10 backups
import os, glob
files = sorted(glob.glob('/opt/netquery/data/ipdb_backups/ipdb-backup-*.xlsx'))
while len(files) > 10:
    os.remove(files.pop(0))

print('OK:', filename, '- Registros:', len(db))
PYEOF
echo "[$(date)] Backup finalizado" >> "$LOG"
