Hola Xavi! Encontré algo en el vpn-honeypots (open-source, no toqué nada en producción). Te lo paso resumido:

**Qué es:** open redirect no autenticado en el honeypot de Citrix (`citrix-gateway/app.py`, función `_abs_url()`, línea ~290, único call site en `catchall()` línea 773).

**Cómo funciona:** cualquier GET a una ruta no reconocida, sin login, con el header `X-Forwarded-Proto: https://evil.com,https` (o directamente `Host: evil.com`), hace que el `Location` del 302 termine apuntando a un dominio arbitrario en vez de volver al propio honeypot. Lo reproduje contra el stack real (`uvicorn` + `asgi.py`, el mismo que arranca `run.sh`), no contra el dev server.

**Por qué pasa:** `proto = request.headers.get("X-Forwarded-Proto", request.scheme).split(",")[0].strip()` nunca valida que sea `http`/`https`, y arma la URL por concatenación de string (`f"{proto}://{request.host}{path}"`). Si el proto ya trae su propio `"://"`, Werkzeug normaliza (`iri_to_uri`) esa mezcla en una URL limpia cuya autoridad es la que metió el atacante — lo confirmé con dos parsers de URL estándar independientes (Python `urlsplit` y el `URL` de Node/WHATWG), ambos coinciden en el host resuelto.

**GlobalProtect no tiene este bug** — sus redirects son strings relativos hardcodeados, nunca arma URLs absolutas con host/scheme.

**PoC (local, loopback, nunca contra tu deploy):**
```
GET /cualquier-ruta HTTP/1.1
Host: 127.0.0.1:18490
X-Forwarded-Proto: https://evil.com,https

→ 302 Found
  Location: https://evil.com//127.0.0.1:18490/vpn/index.html
```
Lo tengo además corrido con una herramienta propia de validación (receipt determinístico, oráculo = parser de URL real, no substring) si querés el JSON completo.

**End-to-end, con receptor real (no solo "el Location apunta afuera"):** levanté un receptor en loopback y seguí el redirect con `curl -L`. El receptor lo confirma en su propio log, independiente de mí:
```
GET /cualquier-ruta HTTP/1.1
X-Forwarded-Proto: http://pancito-demo.local:18500/
→ 302 Location: http://pancito-demo.local:18500/://127.0.0.1:18490/vpn/index.html
→ curl sigue el redirect automáticamente
→ receptor (su log): "GET /://127.0.0.1:18490/vpn/index.html HTTP/1.1" 404 -
```
El 404 es solo porque ese path no existe en mi receptor de prueba — lo que importa es que la request *llegó*. Ya no es "podría redirigir", es "lo vi llegar".

**Severidad:** CWE-601 (open redirect), no XSS ni RCE — no encontré forma de que el valor vuelva a entrar al sistema ni de ejecutar nada, solo de redirigir.

**Lo que NO verifiqué:** si esto es alcanzable contra tu deploy real en Vercel (depende de si tu edge sobreescribe `X-Forwarded-Proto`/`Host` antes de llegar a la función). No lo probé contra producción — prefiero que lo confirmes vos o me digas si querés que lo pruebe con cuidado.

Fix sugerido: allowlist estricta de `proto` a `{"http","https"}` contra `request.scheme`, y nunca aceptar un valor que ya contenga `"://"`. Si querés te paso el PR.
