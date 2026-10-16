# Evaluación de reutilización de repositorios para PANCITO-RED-TEAM

**Fecha de revisión:** 2026-10-10

**Alcance:** selección de repositorios de `~/Downloads/repositorios.md`, `~/Downloads/Telegram Desktop/repositorios2.md.md` y `morluto/rea` (`main` en `a11fbc0df941476767d227dc79447fb676f9abcd`).
**Resultado:** recomendaciones para investigación y diseño; no se copió código ni se agregó ninguna dependencia.

## Resumen

Hay material rescatable principalmente como **fixtures de evaluación, ideas de oráculos deterministas y herramientas externas para el analista**. No conviene convertir un framework general de agentes o de red team en autoridad de PANCITO. La frontera del proyecto sigue siendo la que establece [`AGENTS.md`](../AGENTS.md): catálogo acotado, autorización explícita y un núcleo de decisión determinista, sin LLM, floats ni dependencias externas en valores sellados.

Orden sugerido:

1. **Evaluar primero como material de laboratorio:** AgentDojo para escenarios de inyección indirecta y Atomic Red Team para técnicas que puedan convertirse en replay sintético. No ejecutar atomics importados automáticamente ni tratarlos como prueba de impacto.
2. **Usar scanners como controles offline de desarrollo:** Agent Scan y MCP Scanner para inspirar una revisión de descripciones, esquemas y cambios de herramientas MCP.
3. **Mantener como herramientas externas:** REA, Promptfoo, garak y PyRIT. Pueden asistir investigación o QA de agentes, pero no deben producir ni cambiar un veredicto sellado.
4. **No copiar reglas o código hasta resolver términos particulares:** Sigma Rules, Volatility 3 y Velociraptor tienen condiciones que no se deben resumir como licencias permisivas estándar.

## Qué se verificó y qué no

Las dos listas contienen cientos de enlaces (148 y 267 repositorios GitHub únicos, respectivamente). Esta revisión selecciona los proyectos con relación más directa a pruebas adversariales reproducibles, MCP/LLM, observabilidad y DFIR. Los repositorios restantes **no están evaluados ni aprobados**.

Para los candidatos de la tabla se consultó la licencia identificada por la API de GitHub (`/license`), que devuelve el archivo reconocido y su SPDX cuando puede determinarlo. Se leyó el contenido de las licencias no estándar o con atribución por tipo de activo (REA, Sigma, Volatility 3, Velociraptor y PurpleLlama). Para REA se inspeccionó además el clon de `main` y su archivo `LICENSE`. La licencia indicada se refiere al repositorio/archivo identificado; no garantiza que cada fixture, subdirectorio, modelo, regla o submódulo comparta esos términos. No se hizo una revisión legal ni un inventario completo de dependencias transitivas.

La copia local de REA es superficial y no inicializa submódulos; el resto de los proyectos se revisó por metadatos y archivos de licencia en GitHub, no se clonó ni ejecutó. Antes de incorporar cualquier material hay que fijar commit/tag y digest, releer el archivo de licencia de esa revisión, identificar licencias de datos y dependencias, y registrar atribución en `ATTRIBUTIONS.md`.

## Matriz de candidatos

| Proyecto | Licencia revisada | Qué puede aportar a PANCITO | Decisión sugerida |
|---|---|---|---|
| [REA](https://github.com/morluto/rea) | MIT (`LICENSE`; `package.json` también declara MIT). Tiene submódulos y terceros con términos propios. | Investigación local de binarios, aplicaciones y comportamiento de procesos; evidencia para que un operador entienda mejor el objetivo o una muestra. | **Herramienta opcional externa.** No integrarla al catálogo Red ni al núcleo sellado: su superficie de observación/ejecución local y sus permisos son más amplios que los experimentos loopback y MCP pasivo de PANCITO. Mantener atribuciones si se copia código. |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | MIT (`LICENSE`). | Escenarios de prompt injection indirecta y oráculos que comparan estado final, útiles para diseñar pruebas repetibles de agentes. | **Candidato de laboratorio.** Adaptar el patrón del escenario/oráculo, inspeccionando cada fixture y conservando procedencia. No importar su framework al camino de veredictos. |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | MIT (`LICENSE.txt`). | Catálogo de técnicas y ejemplos de telemetría/validación Blue mapeados a ATT&CK. | **Referencia y fixtures seleccionados.** Convertir manualmente a escenarios sintéticos o replay. No ejecutar sus comandos como efecto lateral de un agente ni ampliar el permiso de objetivos de PANCITO. |
| [Agent Scan](https://github.com/snyk/agent-scan) | Apache-2.0 (`LICENSE`). | Casos de revisión de servidores MCP, descripciones de herramientas, prompt injection y cambios de herramientas. | **Control offline de CI/autoría**, sujeto a revisar alcance, falsos positivos y versión. No como autoridad sobre el veredicto de un caso. |
| [MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Apache-2.0 (`LICENSE`). | Ideas para comparar lo que un servidor declara con su implementación y para revisar riesgos de supply chain. | **Referencia para hardening del puente MCP**. Mantener cualquier evaluación fuera del núcleo y revisar por separado uso de servicios externos, sandbox y telemetría. |
| [Promptfoo](https://github.com/promptfoo/promptfoo) | MIT (`LICENSE`). | Matrices de evaluación, casos adversariales, repetición y ejecución en CI para la capa narrativa/agente. | **QA opcional de agente.** Sus puntuaciones no deben convertirse en evidencia Red/Blue ni reemplazar el oráculo determinista. |
| [garak](https://github.com/NVIDIA/garak) | Apache-2.0 (`LICENSE`). | Banco de probes y detectores para evaluar modelos y entradas. | **Herramienta externa de evaluación**, fijada y aislada. No introducir probes, dependencias o llamadas a modelos en la ruta sellada. |
| [PyRIT](https://github.com/microsoft/PyRIT) | MIT (`LICENSE`). | Patrones de orquestación de evaluaciones adversariales de modelos y gestión de casos. | **Referencia/QA externo.** Seleccionar solo técnicas con amenaza y permiso definidos; no delegar decisiones de PANCITO a sus scorers o modelos. |
| [DeepTeam](https://github.com/confident-ai/deepteam) | Apache-2.0 (`LICENSE.md`). | Organización de categorías de pruebas de seguridad de aplicaciones LLM. | **Referencia de cobertura**, no motor del veredicto. Confirmar versiones, telemetría y dependencias antes de automatizar. |
| [AtomicTestHarnesses](https://github.com/redcanaryco/AtomicTestHarnesses) | BSD-3-Clause (`LICENSE`). | Variaciones de comportamiento para comprobar detecciones, complementarias a los casos Atomic. | **Referencia**. Solo reutilizar fixtures o código tras revisión individual y atribución BSD; no ejecutar por defecto. |
| [Apache CALDERA](https://github.com/apache/caldera) | Apache-2.0 (`LICENSE`). | Ideas para campañas/operaciones Purple y organización de emulación ATT&CK. | **No integrar.** Su orquestación de acciones es más amplia que el modelo acotado de PANCITO; conservar como referencia de producto. |
| [YARA](https://github.com/VirusTotal/yara) | BSD-3-Clause (`COPYING`). | Motor externo opcional para clasificación de artefactos mediante reglas. | **Posible adaptador offline futuro**, aislado del sello y con límites de recursos; revisar licencia de cada regla además de la del motor. |
| [Sigma](https://github.com/SigmaHQ/sigma) | GitHub no asigna un SPDX único. `LICENSE` dice: especificación/logo en dominio público; reglas bajo Detection Rule License (DRL) 1.1. | Catálogo de detecciones para cobertura Blue y mapeos ATT&CK. | **No copiar reglas sin revisar DRL 1.1 y procedencia por regla.** La especificación y el conjunto de reglas no tienen el mismo tratamiento. |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | Licencia propia: “Volatility Software License” v1.0 (`LICENSE.txt`), no SPDX estándar. El texto exige compartir código fuente de cambios, adiciones y software construido con el proyecto. | Análisis de memoria para enriquecer investigaciones DFIR, si PANCITO adopta ese tipo de artefacto. | **Solo herramienta externa por ahora.** No copiar ni enlazar estrechamente hasta análisis legal del alcance de esas obligaciones. |
| [Velociraptor](https://github.com/Velocidex/velociraptor) | GNU AGPL-3.0 (`LICENSE`). | Colección/consulta DFIR de endpoints fuera del laboratorio local. | **No incorporar al servicio ni distribuir integrado** sin decidir obligaciones AGPL y modelo de despliegue. Si se evalúa, hacerlo como sistema externo con interfaz y límites explícitos. |
| [PurpleLlama](https://github.com/meta-llama/PurpleLlama) | `LICENSE` contiene Llama 3.2 Community License Agreement; GitHub no lo identifica como licencia SPDX. | Evaluaciones y materiales relacionados con modelos Meta. | **No asumir licencia MIT/Apache ni transferibilidad general.** Revisar los términos del artefacto específico; no es candidato de código base. |

Los enlaces de cada fila apuntan al repositorio oficial, donde se encuentra el archivo revisado. Para Sigma y las licencias no estándar, el archivo `LICENSE` es especialmente relevante; la etiqueta SPDX de GitHub por sí sola no alcanza.

## Propuestas concretas para PANCITO

### 1. Añadir escenarios de seguridad de agentes como fixtures deterministas

Usar AgentDojo como referencia para representar una tarea legítima, un dato no confiable con instrucciones hostiles, una acción de herramienta observable y un estado esperado. PANCITO puede evaluar el resultado con su propio oráculo y sellar los artefactos propios. El contenido recuperado o devuelto por herramientas se mantiene como **dato no confiable**, nunca como instrucción para el harness.

### 2. Ampliar la cobertura Blue mediante replay, no ejecución automática

Tomar Atomic Red Team como mapa de técnicas y diseñar fixtures sintéticas que ejerciten los analizadores DFIR de PANCITO. Cada fixture debe tener ground truth separado, versión/fuente, hash, detección esperada y caso benigno equivalente. Los comandos de Atomic no deben aparecer como acciones ejecutables automáticamente por el MCP ni como destinos controlados por un modelo.

### 3. Revisar el puente MCP fuera de la decisión sellada

Incorporar un chequeo offline de cambios al catálogo MCP: nombre y esquema exacto, descripción, permisos, ejecución indirecta, archivos que puede leer, llamadas de red y mutaciones. Agent Scan y MCP Scanner pueden aportar casos de prueba. El chequeo informa hallazgos de ingeniería; no modifica puntuación, estado, hash ni sello.

### 4. Dejar REA como herramienta del investigador

REA puede ayudar a analizar una app o binario asociado a una investigación y generar observaciones que el operador adjunte como evidencia con su procedencia. Esa evidencia debe conservar su origen, límites, digest y método de adquisición; la salida de REA no se trata como veredicto ni se pasa sin validación al núcleo. Una integración MCP futura requeriría contratos específicos de lectura/ejecución, autorización por objetivo y límites de recursos.

### 5. Mantener evaluación de LLM en un carril separado

Promptfoo, garak, PyRIT y DeepTeam sirven para medir la capa de agente/narración: resistencia a instrucciones hostiles, filtración, uso fuera de política y calidad de degradación. Sus salidas son métricas de evaluación del producto. El veredicto de cada experimento sigue determinado por la evidencia observada y los oráculos de PANCITO.

## Licencias y procedencia antes de reutilizar

- Registrar repo, URL oficial, commit/tag exacto, SHA-256 del material incorporado, licencia del archivo y fecha de revisión.
- Incluir los avisos MIT/BSD/Apache y textos completos requeridos cuando se copie o distribuya material; registrar cambios cuando la licencia lo exija.
- Separar código, datos, reglas, modelos, pesos, ejemplos y submódulos: pueden tener licencias distintas dentro de un mismo repositorio.
- Para Sigma Rules, Volatility 3 y cualquier licencia personalizada, obtener una decisión legal antes de incluir material en una distribución de PANCITO.
- Para dependencias de runtime, revisar lockfile, transitivas, scripts de instalación, llamadas de red y autoridad de ejecución. Una licencia permisiva no es una evaluación de seguridad de la dependencia.
- Mantener la política vigente de PANCITO: dependencias nuevas no entran al núcleo determinista sellado; cualquier adaptador futuro queda fuera de ese camino y reporta degradación explícita si no puede producir evidencia verificable.

## No evaluados en esta pasada

No se hizo revisión repo por repo de las listas completas ni de los candidatos de OSINT, C2, post-explotación, plataformas de agentes de propósito general y la mayoría de los sistemas DFIR. No deben interpretarse como aprobados por aparecer en las fuentes. Antes de adoptar uno, aplicar la misma revisión de código, autoridad, procedencia, actividad, licencia raíz y licencias de activos individuales.
