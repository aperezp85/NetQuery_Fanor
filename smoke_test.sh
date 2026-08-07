#!/bin/bash
cd /opt/netquery
PASS=0
FAIL=0

check() {
  if [ "$1" = "0" ]; then
    echo "OK   - $2"
    PASS=$((PASS+1))
  else
    echo "FAIL - $2"
    FAIL=$((FAIL+1))
  fi
}

# 1. Servidor responde
curl -sf http://localhost:3000/api/health > /tmp/smoke_health.json
check $? "Servidor responde en /api/health"

# 2. Rutas protegidas rechazan sin login (no deben devolver success:true)
UNAUTH=$(curl -s -X PUT http://localhost:3000/api/multisheet -H "Content-Type: application/json" -d '{}')
echo "$UNAUTH" | grep -q '"success":true'
if [ $? -eq 0 ]; then check 1 "Ruta protegida /api/multisheet rechaza sin login"; else check 0 "Ruta protegida /api/multisheet rechaza sin login"; fi

# 3. BD_Sdwan sin campos ajenos de BD_Servicios (regresion del bug de contaminacion)
node -e '
const ms = require("./data/multisheet.json");
const ajenos = ["Vrf","Wan","Nodo","Puerta","Ip_Admin_Switch","Posicion_Switch","Posicion_Shelf_MC","Posicion_ODF"];
const contaminados = (ms["BD_Sdwan"]||[]).filter(r => ajenos.some(c => c in r));
process.exit(contaminados.length === 0 ? 0 : 1);
'
check $? "BD_Sdwan sin campos ajenos de BD_Servicios"

# 4. SDWAN_COLS sigue siendo dinamico (let, no const)
grep -q "^let SDWAN_COLS" public/index.html
check $? "SDWAN_COLS sigue siendo dinamico"

# 5. PUT /api/multisheet valida coincidencia antes de responder exito
grep -q "if(updated === 0)" server.js
check $? "PUT /api/multisheet valida coincidencia"

# 6. DELETE /api/multisheet valida coincidencia antes de responder exito
grep -q "ms\[sheet\].length === antes" server.js
check $? "DELETE /api/multisheet valida coincidencia"

# 7. openModalAgregar resetea _servicioSheet (bug del +Agregar guardando en hoja incorrecta)
grep -q "window._servicioSheet = 'BD_Servicios';" public/index.html
check $? "openModalAgregar resetea _servicioSheet"

# 8. Rutas de credenciales admin existen
grep -q "app.get('/api/admin-creds/:key'" server.js
check $? "Ruta /api/admin-creds existe"

echo ""
echo "Resultado: $PASS pasaron, $FAIL fallaron"
exit $([ $FAIL -eq 0 ] && echo 0 || echo 1)
