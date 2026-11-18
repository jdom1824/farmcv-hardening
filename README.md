# FarmCV — API y portal de administración

FastAPI asíncrona con JWT de administrador para escrituras, consultas y verificación públicas. `app.main:app` expone la API; `app.admin_portal:app` añade el portal público y el panel administrativo. No requiere Docker.

## Ejecución

Usar Python 3.13, crear un entorno virtual e instalar las dependencias directas fijadas en `requirements-validated.txt` (el archivo no es un lock completo de dependencias transitivas). Copiar `.env.example` a `.env` y sustituir todos los valores de ejemplo. Configurar un hash de contraseña PBKDF2-HMAC-SHA256 con 310 000 iteraciones y sal aleatoria de 16 bytes (`base64url(sal)$base64url(digest)`), un secreto JWT aleatorio e independiente, la wallet propietaria del contrato y `PUBLIC_BASE_URL`. Este último debe ser el origen HTTPS público que abrirán los QR; para pruebas locales se admite HTTP solo en loopback. Nunca reutilizar una clave de prueba en una red con fondos reales.

```bash
cd /path/to/farmcv-hardening
python3.13 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-validated.txt
cp .env.example .env
# Editar .env y reemplazar los valores de ejemplo antes de iniciar.
uvicorn app.admin_portal:app --host 127.0.0.1 --port 8010 --workers 1 --no-proxy-headers
```

La configuración del servicio determina la red y el contrato. Para pruebas aisladas debe usarse exclusivamente Hardhat local (chain ID 31337), con credenciales y almacenamiento descartables; nunca se debe reutilizar la cuenta predeterminada de Hardhat en una red con fondos. Swagger: `/docs`; esquema: `/openapi.json`. Use un único proceso escritor. Ver [transacciones persistentes e idempotencia](TRANSACTIONS.md): las escrituras requieren `Idempotency-Key` y admiten `Prefer: respond-async` para aceptación inmediata.

## Cifrado automático (entrada recomendada del administrador)

`POST /farm-cv` y `PUT /farm-cv/{farm_id}` aceptan ahora un JSON sin cifrar con `farm_id`, `cv` y `polygon`. Ver [ejemplo](examples/plaintext-farm.json). El administrador solo aporta datos y su JWT: no proporciona claves, hashes ni textos cifrados.

La API valida el sobre y la estructura básica del polígono, normaliza los campos con sus valores por defecto, añade `farm_id` al CV, serializa JSON canónico (UTF-8, claves ordenadas, sin espacios ni NaN), calcula SHA-256 y cifra ambos documentos con Fernet antes de estimar gas, firmar y transmitir. La validación geométrica es básica: límites de coordenadas, cierre y número de puntos; no certifica topología, linderos ni propiedad de la finca.

La clave del servidor se provisiona **una sola vez**:

```bash
python scripts/provision_encryption.py
```

Se conserva en `.secrets/cv-fernet.key` (0600; directorio 0700). Puede configurarse otra ruta mediante `CV_ENCRYPTION_KEY_FILE`. No se imprime ni se devuelve al cliente. El script nunca reemplaza una clave existente. Si falta, está dañada o sus permisos no son seguros, el flujo automático devuelve 503 antes de enviar la transacción. Nunca se genera una clave nueva automáticamente al arrancar.

**Conservar una copia segura de la clave:** perderla impide descifrar los registros existentes. La rotación con un historial de claves y la restauración desde un gestor de secretos quedan para la etapa operativa. Los endpoints públicos continúan devolviendo ciphertext/hashes, no los documentos descifrados. No se añadió un endpoint público de descifrado.

El formato anterior con `encrypted_cv`, `encrypted_polygon` y hashes sigue disponible para compatibilidad; no es necesario para el administrador. Mezclar ambos formatos o enviar una clave en el JSON se rechaza. Máximo del nuevo documento normalizado: 16 KiB. Las referencias de fotografías pueden incluirse en `cv.photos`; no se incluyen los bytes del JPG en blockchain.

Enviar información real únicamente por un transporte protegido. El cifrado on-chain no sustituye la protección de la conexión ni una política que evite registrar cuerpos de solicitudes sensibles. Cualquier despliegue accesible externamente debe usar HTTPS.

## Validación reproducible

```bash
cd /path/to/farmcv-hardening
python tests/validate_hardhat.py
```

La suite exige Hardhat y chain ID 31337, despliega un contrato nuevo y usa credenciales de administrador efímeras. Prueba cifrado antiguo con clave efímera y cifrado automático con la clave persistente del servidor. Crea datos sintéticos, fotografías y operaciones persistentes. Desactiva temporalmente el autominado para comprobar estados pendientes/fallidos y lo restaura mediante `finally`. No ejecutarla simultáneamente con otros usuarios del nodo. No cambia `.env`, ni reinicia o limpia la cadena.

Los resultados con latencia, hashes de transacciones, gas y eventos quedan en `test-results/hardhat-validation.json`. Se prueba primero mediante transporte ASGI y después con dos procesos Uvicorn sucesivos sobre HTTP loopback. Las claves no se incluyen en los resultados.

## Alcance y límites

- Registro y actualización aceptan tanto el flujo automático recomendado como el sobre cifrado antiguo. Las pruebas cubren ambos y descifran en el servidor para verificar el resultado sin exponer la clave.
- La prevalidación pública es libre de efectos secundarios. En el formato nuevo valida campos, JSON, tamaño y estructura básica del polígono, sin necesitar clave ni enviar transacciones; en el formato antiguo solo puede validar el sobre cifrado.
- JPEG se decodifica, se almacena en disco y se devuelve su SHA-256 y URI lógica. No existe todavía un endpoint de descarga ni una asociación automática a la finca: la referencia se incorpora al CV antes de cifrarlo.
- El contrato conserva textos cifrados, hashes y metadatos; las fotografías originales permanecen fuera de la cadena.
- Las operaciones de escritura tienen base SQLite, intención persistida, historial, idempotencia y reconciliación en segundo plano. Ver [contrato HTTP y límites operativos](TRANSACTIONS.md).
- Las pruebas incluyen reinicio por SIGKILL y recuperación de una operación pendiente, además de fallos simulados de persistencia. No equivalen a recuperación de un disco averiado ni restauración completa de un backup.
- El portal limita el cuerpo de solicitudes a 11 MiB y el login a 4 KiB; admite hasta dos uploads simultáneos por proceso en ambas rutas de foto (el siguiente recibe 429). Los límites generales (600 solicitudes/min) y de fallos de login (10/min) son por identidad IP de cliente, con estado en memoria y un máximo de 4096 identidades recientes por proceso; al superar ese tope se expulsa la identidad menos reciente. Para acotar PBKDF2, permite hasta cuatro verificaciones de login simultáneas en el proceso; el exceso recibe `429 Retry-After: 1` sin penalización por ventana. Requiere un worker.
- La identidad se toma del peer TCP directo. `X-Forwarded-For` se ignora por defecto; solo se procesa si el peer pertenece a `TRUSTED_PROXY_CIDRS`, una lista opcional separada por comas de CIDRs/IP de proxies explícitamente confiables. Se rechazan las rutas catch-all `/0`. La cadena se recorre de derecha a izquierda, descartando los saltos confiables. Configurar únicamente tras verificar la topología real y que el proxy reemplaza el XFF entrante o agrega al final el peer TCP real; no hay CIDRs de producción preconfigurados. Si el servicio está detrás de un proxy compartido y la lista queda vacía, todos sus usuarios comparten la identidad del peer del proxy y su límite; resolver esta configuración es un pendiente de despliegue. Si el servidor ASGI no informa un peer IP válido, se usa la identidad común `unknown`. Desactive también la reescritura automática de proxy headers en el servidor ASGI (la orden Uvicorn anterior usa `--no-proxy-headers`); si se requiere activarla, su allowlist debe estar alineada con la de la aplicación y validada junto con la topología.
- Los limitadores son protección local por IP, no defensa contra denegación de servicio distribuida: ante muchas IP distintas, el límite de 4096 identidades puede expulsar estado antiguo y se deben configurar límites de ingreso adecuados en la infraestructura una vez conocida la topología.
- Esta suite no certifica preparación para Internet/producción. Siguen pendientes la validación de la topología/CIDRs de proxy, HTTPS y cabeceras de despliegue, gestión/rotación/recuperación de secretos, backup restaurable, supervisión de servicio y una prueba sostenida en hardware objetivo con datos sintéticos de escala. Las lecturas API se exponen mediante allowlist exacta; devuelven ciphertext y metadatos, nunca el CV descifrado.
