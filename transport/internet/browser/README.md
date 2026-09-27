# Мимикрия под браузер (по мотивам enetx/surf)

## Что отпечатывается и что из этого видит DPI

| Слой | Что в отпечатке | Кто видит | Что делает surf | Что сделано здесь |
|---|---|---|---|---|
| TLS ClientHello (JA3/JA4) | шифры, набор и **порядок** расширений, группы, key_share, sigalgs, ALPN, GREASE, ECH GREASE, trust_anchors | **DPI** (открытым текстом) | свой спек Chrome 152 поверх uTLS, перемешивание на каждое соединение, случайный GREASE в sigalgs | перенесено 1-в-1, `chrome` и пустой отпечаток = Chrome 152 |
| TLS-сессия | PSK/resumption, session ticket | DPI | кэш сессий, PSK-расширение | нет: Xray не возобновляет сессии (как Chrome на первом заходе) |
| HTTP/2 preface (Akamai h2) | порядок и значения SETTINGS, WINDOW_UPDATE соединения, приоритет в HEADERS, порядок псевдозаголовков, начальный stream id | сервер/CDN (внутри TLS) | форк x/net/http2 (enetx/http2) | значения, порядок SETTINGS, WINDOW_UPDATE и приоритет HEADERS — для XHTTP h2, REALITY-паука, DoH, geodata |
| HTTP-заголовки | набор, порядок, `sec-ch-ua`, `sec-fetch-*`, `priority`, `accept-encoding` | сервер/CDN | упорядоченные заголовки по методу и ОС | в Xray уже было (`common/utils/browser.go`); убран `DNT: 1`, которого Chrome по умолчанию не шлёт |
| HTTP/3 / QUIC | QUIC transport params, H3 SETTINGS, GREASE | DPI (Initial) и сервер | только H3 SETTINGS, QUIC — обычный quic-go | не трогал: у XHTTP h3 уже есть `ChromeParrot` в quic-go Xray |
| multipart boundary | формат границы | сервер | WebKit/Firefox | к Xray не относится |

Для ТСПУ важен в первую очередь **ClientHello**: по разбору в nodeSetup (`TSPU.md` §2.2,
`BLOCKING.md` §12-13) решение принимается на hello, до первого байта данных, а настоящий
Chrome 152 проходит там, где uTLS-`chrome` режут.

## Почему uTLS-`chrome` ловят, а Chrome 152 нет

uTLS отдаёт `HelloChrome_133`. Его JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd` совпадает с
Chromium ≤141 (снято с Chromium 141 в этой же среде), а настоящие Chrome 150+ шлют уже другой hello:

- `signature_algorithms` начинается с GREASE, дальше ML-DSA-44/65/87 (0x0904-0x0906);
- всегда есть `trust_anchors` (0xca34, draft-ietf-tls-trust-anchor-ids), 206 байт ID корней Chrome Root Store;
- итого 17 расширений вместо 16: JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`
  (в базе Scrapfly значится как настоящий Chrome).

В 2026 году старый JA4 почти не встречается у браузеров — зато его шлют все прокси-клиенты на uTLS.

## Что изменено в коде

- `transport/internet/tls/fingerprint_chrome.go` — спек Chrome 152 (из surf), новый на каждое соединение:
  перемешанные расширения (GREASE по краям), случайный GREASE в sigalgs, GREASE ECH 144-240.
- `transport/internet/tls/tls.go` — `NewUConn`: uTLS + собственные спеки Xray; `chrome`, `""` и
  `hellochrome_152` → Chrome 152; старый доступен как `hellochrome_133`. DoH, ECH-запросы и загрузка
  geodata тоже ходят с Chrome 152.
- `transport/internet/reality/reality.go` — REALITY-клиент через `NewUConn`.
- `transport/internet/browser` — HTTP/2-профили Chrome 152 и Firefox 148 (значения из surf):

  | | SETTINGS | WINDOW_UPDATE | HEADERS priority |
  |---|---|---|---|
  | Chrome | `1:65536;2:0;4:6291456;6:262144` | 15663105 | excl, dep 0, weight 256 |
  | Firefox | `1:65536;2:0;4:131072;5:16384` | 12517377 | dep 0, weight 42 |
  | Go (было) | `2:0;4:4194304;5:16384;6:10485760` | 1073741824 | нет |

  Значения выставляются настройками x/net/http2, поэтому управление потоком и HPACK клиента
  соответствуют объявленному. Обёртка соединения только переставляет SETTINGS, убирает то, чего
  браузер не шлёт (без смены семантики), и добавляет приоритет в HEADERS. Профиль выбирается по
  `fingerprint`: chrome/edge/qq/360/пусто → Chrome, firefox → Firefox, safari/ios/random → Go как было.
  Выключить: `XRAY_BROWSER_H2=off`.

## Что проверено (локально, без ТСПУ)

- юнит-тесты: JA4, перемешивание (≥10 разных порядков из 20), рукопожатие с Go TLS 1.3 сервером,
  кадры HTTP/2 на проводе, 20 МБ вниз/вверх через h2 с профилями, запись кадров по одному байту;
- e2e: REALITY+Vision, VLESS TLS+Vision, XHTTP TLS, XHTTP REALITY, WS TLS, gRPC TLS, trojan TLS ×
  (chrome, пусто, hellochrome_152, hellochrome_133, firefox, safari, edge, qq, randomized) — маленький
  запрос ×3 и 5 МБ со сверкой хеша; новый клиент ↔ стоковый сервер той же версии — всё зелёное;
- hello с провода: 1943-2039 байт, JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`, заголовок записи `16 03 01`.

## Ограничения и что знать

- **REALITY-сервер в текущем upstream (xtls/reality 2026-09-08) отвергает hello без X25519MLKEM768.**
  `edge`/`qq`/`360`/`ios` (517 байт, без PQ) с REALITY на таком сервере не работают вообще — и на
  стоковом Xray тоже. С TLS/XHTTP через nginx они работают.
- `trust_anchors` — байты конкретной сборки Google Chrome 152.0.7977; через пару версий их надо
  обновлять (surf обновляет вместе с версией).
- WebSocket по-прежнему шлёт ALPN только `http/1.1` (JA4 `…h1…`) — браузер так не делает. WS устарел.
- gRPC ходит через grpc-go со своим h2-отпечатком — не трогал.
- Порядок псевдозаголовков h2 (`m,a,s,p` у Chrome) остаётся Go-шным (`a,m,p,s`): переставлять его
  на лету значит перекодировать HPACK; видно только серверу/CDN.
- `firefox` остаётся uTLS `HelloFirefox_148` — surf использует его же, улучшений там нет.
- Версия Chrome в User-Agent считается по дате (`common/utils/browser.go`) и может не совпадать с 152.
