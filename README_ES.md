[English](README.md) · [Español](README_ES.md) · [Technical README](TECHNICAL_README.md) · [Arquitectura interactiva](docs/pancito-architecture.html)

# PANCITO-RED-TEAM

La automatización ofensiva tiene un problema de evidencia: una herramienta
puede producir un relato convincente sin demostrar que el objetivo cambió, que
un control falló o que Blue observó el comportamiento.

PANCITO-RED-TEAM es un toolkit acotado de validación adversarial para
laboratorios de seguridad autorizados. Ejecuta experimentos pequeños y
reproducibles cuyo objetivo siempre es defensivo: probar un control, preservar
lo observado, limpiar el estado creado y no afirmar más de lo que permite la
evidencia.

Los experimentos HTTP activos actuales sólo aceptan objetivos loopback
literales. El modelo puede elegir qué investigar o narrar un resultado ya
producido; no puede decidirlo, puntuarlo, hashearlo, sellarlo ni suprimirlo.

## Cómo se comporta un experimento

```text
manifiesto autorizado
        ↓
control funcional ──falla──> INCONCLUSIVE
        ↓ funciona
celda negativa acotada
        ↓
read-back / oráculo determinista
        ↓
cleanup verificado ──falla──> MANUAL_ACTION_REQUIRED
        ↓
recibo Red acotado + evaluación Blue independiente
```

Una respuesta HTTP exitosa no se convierte automáticamente en hallazgo. Por
ejemplo, el experimento de ingreso de archivos sólo confirma persistencia si la
metadata autenticada reproduce el tamaño y SHA-256 exactos de una muestra
sintética inerte. Si falta el identificador, falla el read-back o no puede
verificarse la limpieza, el resultado sigue siendo `INCONCLUSIVE`.

## Diferencia de diseño

La tabla compara dos decisiones de implementación. No afirma que todos los
productos agentic de seguridad utilicen el primer diseño.

| Dimensión | Ejecutor de modelo de propósito general | Implementación actual de PANCITO |
|---|---|---|
| Superficie de acción | El modelo puede componer comandos o llamadas | El código selecciona un catálogo cerrado de capacidades |
| Objetivo activo | Un dato de runtime puede nombrar un destino de red | Las pruebas HTTP activas exigen un origen loopback literal |
| Resultado evidencial | La interpretación del modelo puede convertirse en reporte | Código determinista produce el resultado antes de la narración |
| Observación ambigua | Suele resolverse mediante interpretación textual | `INCONCLUSIVE` o `MANUAL_ACTION_REQUIRED` explícitos |
| Prueba con cambios | El cleanup depende del workflow generado | Read-back, restauración y verificación forman parte del experimento |
| Objetivo Blue | La detección puede revisarse después | Cada paso lleva correlación y detección se evalúa aparte de prevención |

## Qué está implementado

| Capacidad | Pregunta defensiva | Frontera de evidencia |
|---|---|---|
| Replay de telemetría hostil | ¿La ruta DFIR sellada detecta las técnicas ATT&CK esperadas? | Fixtures versionadas, catálogo fijo y cadena de custodia verificada |
| Diferencial BOLA | ¿Un principal autenticado puede leer el objeto de otro? | Controles owner/peer antes de una celda cross-principal |
| Diferencial de autenticación | ¿Datos protegidos sobreviven credenciales ausentes o inválidas? | Un 2xx no alcanza sin observar el canario protegido |
| Cambio de estado público | ¿Una identidad anónima o inválida puede mutar un campo? | Read-back autenticado y restauración verificada |
| Mass assignment / BOPLA | ¿Un actor de bajo privilegio puede modificar una propiedad protegida? | Control sobre campo permitido, read-back del observador y restauración verificada de ambos campos |
| Ingreso de archivos | ¿Storage acepta bytes incompatibles con tipo o tamaño? | Tres muestras inertes, digest/tamaño exactos y borrado verificado |
| Diferencial de evasión forense | ¿Los sensores SIFT distinguen rastros conocidos de timestomp y borrado de logs frente a un control limpio? | Tres celdas sintéticas propias del módulo; ground truth exacto separado de observaciones no selladas |
| Antiforense Prefetch | ¿SIFT distingue ejecución sospechosa y eliminación selectiva de Prefetch? | Control limpio de diez archivos más celdas fijas de ejecución y borrado; sólo archivos temporales inertes |
| Evasión Registry | ¿SIFT distingue persistencia Run-key sospechosa y colisión de timestamps? | Hechos sintéticos a nivel parser; sin hive, proceso RegRipper, comando ni payload de entrada |
| Auditoría de composición timeline | ¿Los resúmenes productivos Memory/MFT preservan identidad suficiente para causalidad cross-source? | Los controles positivos pasan, pero el par con forma productiva hoy reporta `FALSIFIED`; no se afirma impacto sobre el veredicto sellado |
| Triage OpenAPI | ¿Qué rutas declaradas merecen un experimento acotado? | Análisis pasivo local; cada resultado sigue siendo candidato, no hallazgo |
| Evaluación Purple | ¿Blue observó y alertó sobre la conducta ejecutada? | Prevención Red y detección Blue permanecen separadas |

La [arquitectura interactiva](docs/pancito-architecture.html) muestra los
componentes y fronteras de confianza. La
[especificación con evidencia de código](docs/pancito-architecture.architecture.json)
está versionada junto al artefacto.

## Probar el laboratorio de replay

Requiere Python 3.10 o posterior.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python3 -m pytest tests/test_offensive_engagement.py \
  tests/test_offensive_replay.py tests/test_determinism.py
```

Ejecutar el replay incluido, sin objetivo vivo:

```python
from offensive.engagement import load_engagement
from offensive.replay import ReplayCampaign

plan = load_engagement("examples/engagement.replay.json")
receipt = ReplayCampaign(
    plan.to_grant(),
    out_dir="offensive-runs",
).run("process-hollowing-timestomp")
```

`offensive-runs/` está ignorado porque contiene evidencia generada. El grant de
ejemplo sólo autoriza el laboratorio de replay incluido.

Para preparar el entorno y usar el servicio heredado opcional, ver
[INSTALL.md](INSTALL.md). Los manifiestos loopback y contratos CLI están en el
[Technical README](TECHNICAL_README.md#command-line-boundaries).

## Evidencia de estas afirmaciones

- [Determinismo](tests/test_determinism.py): reproduce resultados sellados en
  procesos nuevos con semillas de hash diferentes.
- [Replay ofensivo](tests/test_offensive_replay.py): prueba catálogo fijo,
  presupuesto, custodia y oráculo Blue determinista.
- Las suites de [BOLA](tests/test_bola_differential.py),
  [autenticación](tests/test_authn_differential.py),
  [cambio de estado](tests/test_state_change_differential.py),
  [mass assignment](tests/test_mass_assignment_differential.py) e
  [ingreso de archivos](tests/test_file_ingress_differential.py) prueban
  controles, celdas negativas y degradación honesta.
- [Evaluación Purple](tests/test_purple_cli.py): liga las afirmaciones Blue a
  los artefactos Red y Blue exactos que fueron evaluados.
- El [diferencial de evasión forense](tests/test_forensic_evasion_differential.py)
  prueba el parser/analyzer MFT y el detector de cadenas de eventos reales de
  SIFT contra ground truth sintético fijo, sin promover el sensor a veredicto.
- Las pruebas diferenciales de [Prefetch](tests/test_prefetch_evasion.py) y
  [Registry](tests/test_registry_evasion.py) ejercitan dos familias SIFT más
  bajo el mismo contrato de control primero.
- Las [pruebas de composición timeline](tests/test_timeline_evasion.py)
  reproducen pérdida de identidad en el contrato productivo y conservan la
  predicción falsificada como resultado de primera clase, documentado en la
  [nota de auditoría](docs/timeline-composition-audit.md).
- El [recibo visual de arquitectura](docs/pancito-architecture.visual-check.json)
  registra contención de escritorio y capturas del diagrama entregado.

Estas pruebas respaldan las propiedades que ejercitan; no demuestran que todo
objetivo o despliegue sea seguro.

## Documentación relacionada

- [Technical README](TECHNICAL_README.md) — invariantes, fronteras de confianza,
  protocolos, contratos, limitaciones, comandos y mapa del repositorio.
- [README en inglés](README.md) — documento principal del proyecto.
- [Arquitectura interactiva](docs/pancito-architecture.html) — mapa explorable
  con procedencia hacia el código.
- [Investigación upstream](UPSTREAM_RESEARCH.md) — proyectos revisados,
  commits, licencias e ideas adaptadas sin copiar código fuente.
- [Atribuciones](ATTRIBUTIONS.md) — procedencia heredada y de terceros.

## Licencia

PANCITO-RED-TEAM es un toolkit de investigación y pruebas adversariales de
seguridad. Se publica para estudio, experimentación e investigación de
seguridad no comercial. El uso comercial, la redistribución y las obras
derivadas requieren una licencia escrita separada de la autora.

El trabajo original de PANCITO-RED-TEAM se publica bajo PolyForm Strict 1.0.0.
Los componentes heredados y de terceros mantienen sus propios términos. Ver
[LICENSE](LICENSE), [LICENSES/](LICENSES/) y [ATTRIBUTIONS.md](ATTRIBUTIONS.md).
Esos textos legales prevalecen si este resumen difiere de ellos.
