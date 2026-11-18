# Validación de procesos asíncronos y caché — FarmCV

**Resultado: PASS**, para el alcance local descrito aquí. No constituye autorización de despliegue ni certificación de capacidad máxima.

## Entorno y alcance

- Rama `codex/farmcv-hardening`; base solicitada `6a974e8`; commit final de código probado: `c787d80`.
- API `app.admin_portal:app`, ciclo de vida completo, un proceso Uvicorn; Hardhat `2.28.6`, chain ID `31337`, RPC limitado a `127.0.0.1:18545`; API de ensayo en `127.0.0.1:18546`.
- Datos, credenciales y fincas sintéticos; SQLite temporal. No hubo acceso a Radxa, Base Sepolia ni producción, ni despliegues.
- La corrida de cinco minutos se lanzó con `FARMCV_TEST_ROOT` apuntando a la rama en `c787d80`. El JSON generado por el harness conserva por error el SHA base `6a974e8` como metadato hardcodeado; no usar ese campo para identificar el código ejecutado.

## Pruebas y resultado

- Suite unitaria/regresión: **60/60** pasaron.
- Integración Hardhat del backend y outbox: **198/198** pasaron.
- Integración del portal: **34/34** pasaron.
- Integración de ciclo de vida, lecturas concurrentes, RPC y reorganización: **70/70** pasaron.
- Ventana de carga mixta de **300,393 s** con indexador, refresher y refrescos de caché activos; 12 fincas sintéticas precargadas. Búsqueda, paginación y lecturas ocurrieron mientras SQLite se actualizaba.
- Consentimiento: la revocación dejó de exponerse tras la confirmación; el perfil no reapareció hasta que se refrescó el registro con consentimiento vigente. Suspensión ocultó la finca y reactivación la restituyó después del refresco.
- Interrupción RPC sintética de 35 s: el catálogo local siguió respondiendo; el endpoint que requería RPC produjo el error controlado esperado; indexador y refresher observaron el fallo y se recuperaron al restablecer Hardhat.
- Reorganización de un bloque, dentro del solapamiento configurado de **128 bloques**: el indexador eliminó el evento huérfano; la consulta rebajó el recibo obsoleto a `unknown`; el mismo hash/operación se reconcilió y confirmó de nuevo, sin duplicar la finca ni la operación.

## Métricas observadas

| Medición | Resultado |
| --- | ---: |
| Solicitudes de lectura durante la ventana | 1.812 (6,032 req/s) |
| Concurrencia máxima del generador | 4 |
| HTTP durante la carga | 1.812 × 200; 0 errores de transporte/HTTP |
| Latencia p50 / p95 / p99 | 10,246 / 16,039 / 20,164 ms |
| CPU media / pico muestreado | 3,58% / 11,4% |
| RSS pico muestreado | 94,2 MiB (296 muestras) |
| Invalidaciones de `confirmed_hints` / catálogo público | 6 / 53 |
| Reconstrucciones del snapshot público | 19; duración p50/p95/p99: 1,069 / 2,063 / 2,160 ms |
| SQLite, total inicial → final | 447.720 → 286.720 bytes (−161.000 bytes) |
| Avisos RPC por la interrupción inducida | 10 refresher + 1 indexador; ambos recuperados |
| Outbox al cierre | 18 operaciones, todas confirmadas; 0 grupos idempotentes duplicados |

El tamaño de SQLite bajó durante la ventana —compatible con checkpoint/reducción del WAL—, por lo que no se observó crecimiento neto en este ensayo. Las cifras de CPU/RSS corresponden al host local de pruebas, no a la Radxa.

## Defectos corregidos

1. **Recibo confirmado desaparecido tras reorganización.** La operación podía seguir mostrándose como confirmada aunque el bloque ya no fuera canónico. En `5c0aba3` la consulta de reconciliación elimina el resultado obsoleto, persiste `unknown` y conserva bytes firmados/hash/nonce para que el escritor único reintente el mismo envío. Añadida regresión unitaria e integración de reorganización.
2. **GET con efecto de escritura en una operación preparada.** La primera integración completa detectó que consultar una transacción preparada ausente podía llegar a retransmitirla. En `c787d80` las consultas de solo lectura retornan sin broadcast para estados no terminales; solo los recibos terminales ausentes se degradan a `unknown`. Añadida regresión y la integración pasó 198/198.

## Decisión y límites

**PASS** para consistencia funcional de una instancia y el nivel de concurrencia probado. No se detectaron duplicados, pérdidas de estados ni exposición posterior al punto de confirmación definido por estas pruebas.

Este ensayo no determina el máximo de usuarios ni el punto de saturación: la carga fue moderada y tuvo como máximo cuatro solicitudes simultáneas del generador. No prueba concurrencia de varios workers, límites reales de proveedores RPC, reorganizaciones más profundas que 128 bloques, cortes prolongados/pérdida de energía ni presión de disco. Antes de staging conviene repetir el perfil de carga en hardware representativo (Radxa o servidor destino), acordar un umbral de latencia y ejecutar una prueba prolongada de crecimiento de SQLite/WAL. La detección de recibos terminales reorganizados se activa al consultar/reconciliar esa operación; no se hizo una auditoría periódica de todos los recibos terminales inactivos.

El nodo Hardhat y el servidor local de prueba quedaron detenidos al terminar. El código probado corresponde a `c787d80`; este informe se mantiene como documentación separada y no altera artefactos de runtime.
