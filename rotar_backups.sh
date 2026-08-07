#!/bin/bash
# Borra backups de multisheet.json con más de 90 dias
find /opt/netquery/data -name "multisheet.backup.*.json" -mtime +90 -print -delete >> /opt/netquery/data/rotacion_backups.log 2>&1
echo "$(date): rotacion ejecutada" >> /opt/netquery/data/rotacion_backups.log
