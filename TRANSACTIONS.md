# Transacciones persistentes y asincronía

Registro, actualización y cambio de estado requieren `Idempotency-Key` (8-128 caracteres: letras ASCII, números, guion, guion bajo, dos puntos o punto). Se recomienda un UUID generado por el cliente para **cada operación lógica**, conservado hasta conocer el resultado. El administrador no debe generarlo manualmente: lo hace el cliente que consume la API.

Enviar también `Prefer: respond-async` para guardar la operación y devolver `202` sin esperar al RPC. La respuesta incluye `operationId`, estado `queued`, `txHash` inicialmente nulo y `Location: /operations/{operationId}`. Un trabajador iniciado con FastAPI procesa y reconcilia las operaciones persistentes.

Sin esa preferencia, se intenta preparar y enviar dentro de la solicitud, sin esperar confirmaciones. Puede devolver `200 submitted`, `202 queued` si otro escritor tiene el bloqueo, o un error recuperable con `operationId`. **HTTP 200/202 no implica confirmación blockchain.**

- Misma clave y contenido: devuelve la misma operación; no cifra de nuevo ni crea otra transacción.
- Misma clave con contenido/acción diferente: `409`.
- Clave ausente o inválida: `422`; las escrituras siguen exigiendo JWT.
- Ante `503` con `operationId`, consultar la operación o repetir con la misma clave. No crear otra clave para el mismo intento.
- Dos claves diferentes representan dos intenciones diferentes, aunque sus datos coincidan. La deduplicación exige conservar la clave y la base.

## Consultas públicas

| Endpoint | Resultado |
|---|---|
| `GET /operations/{operationId}` | Último estado e historial persistidos; funciona sin RPC. |
| `GET /transactions/{txHash}` | Reconcilia la operación conocida, o consulta el nodo para transacciones no indexadas de este contrato. Con RPC caído, una operación conocida conserva su estado anterior y un aviso; no es una confirmación nueva. |
| `GET /farm-cv/{farmId}/transactions?limit=20&offset=0` | Historial por finca, paginado, máximo 100 elementos. |

Estados: `queued → prepared → submitted → pending/confirming → confirmed/failed`. `unknown` indica envío incierto, `rejected` rechazo antes del envío y `replaced` nonce consumido por otra transacción que exige revisión. Cada cambio se guarda con su fecha.

### Contrato ausente o incompatible

`blocked_configuration` conserva una intención cuyo contrato no tiene código o no responde a la interfaz esperada. La escritura devuelve HTTP 503 con `operationId`, `detail` y `error.code=CONTRACT_UNAVAILABLE`. El trabajador no reintenta ese estado, incluso después de reiniciar la API; las consultas públicas tampoco lo reanudan.

Después de corregir el contrato en el mismo destino, el cliente puede repetir la solicitud autenticada con el mismo contenido y la misma `Idempotency-Key`, **sin `Prefer: respond-async`**, para revalidar y procesar la intención. Repetir con la preferencia asíncrona solo devuelve el bloqueo conservado. Un cambio de red o dirección crea otro ámbito: nunca migra la intención anterior. Revisar manualmente el caso antes de crear una nueva intención en otro destino.

La comprobación previa verifica código y llamadas `owner()` y `farmExists()`, y normaliza errores de decodificación al preparar/procesar la operación. No es una prueba exhaustiva de equivalencia de bytecode ni una auditoría del contrato. No requiere migración de esquema: el estado se guarda en la columna de texto existente.

## Persistencia y recuperación

SQLite guarda el sobre cifrado, hash de la solicitud, nonce, hash y bytes firmados **antes del envío**. No guarda JWTs, claves privadas ni el CV recibido por el nuevo flujo en claro. Los datos internos y la clave de idempotencia no aparecen en las consultas públicas. El formato antiguo presupone que su caller aporta textos realmente cifrados, como antes.

Base: `storage/transactions/operations.sqlite3`, permisos 0600, WAL y `synchronous=FULL`. Configurable con `TRANSACTION_DB_FILE`; usar disco local persistente, no NFS. `TRANSACTION_POLL_SECONDS` define el intervalo nominal, 2 segundos por defecto; la duración real depende de la carga y del RPC.

Tras terminar el proceso, el siguiente arranque consulta los hashes guardados. Si el nodo desconoce una transacción y el nonce no ha sido consumido, se reenvían **los mismos bytes firmados**, manteniendo nonce, hash e intención. Es la retransmisión de la misma transacción, no otra escritura. No se ajusta automáticamente el gas ni se firma una sustitución.

Para este despliegue usar un proceso Uvicorn (`--workers 1`). Existe también un bloqueo de archivo entre procesos del mismo equipo que comparten la base local; no se ofrece coordinación distribuida entre servidores o bases independientes. Dedicar la wallet a este escritor.

Conservar la base y la clave de cifrado en los respaldos. Con WAL activo no copiar solo el `.sqlite3`: utilizar la API de backup de SQLite o detener el servicio correctamente. No resetear Hardhat y reutilizar direcciones de contrato con un historial anterior sin separar ambas ejecuciones.

## Alcance

La confirmación usa el umbral configurado; no certifica finalidad absoluta. No se implementó seguimiento continuo de reorganizaciones después del estado terminal, ajuste de comisiones, cancelación administrativa, migración multihost ni recuperación por corrupción/pérdida física del disco. El historial incluye las operaciones de la API; no indexa automáticamente todas las escrituras externas al contrato.

No existe garantía universal de «exactamente una vez» frente a pérdida de la base, claves de idempotencia distintas, escrituras externas con la misma wallet o reinicio de la cadena. La protección implementada se basa en intención persistida, clave estable, nonce coordinado y retransmisión del mismo hash.
