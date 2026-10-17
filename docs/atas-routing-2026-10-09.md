# ATAS X routing audit — 2026-10-09

This records the 2026-10-09 verification run. Application versions, selected
routes and connection states below are historical observations.

ATAS X login uses literal server IPs as well as domains. Covering its website or
update hostname alone does not cover authentication. Bind the reviewed endpoints
to the existing manually selected `金融加密` policy; preserve Binance's separate
policy and the user's existing node selections.

Evidence: installed ATAS X `8.0.15.654`, its `OFT.Localization.dll`, the public
server cache `AvaliableServers.cnf`, and local application logs. No account names,
passwords, exchange API keys, proxy nodes, or full private configs belong here.

## Endpoint coverage

| Function | Endpoint | Coverage |
| --- | --- | --- |
| Automatic server selection | `auto.platform.atas.net:6214` | `DOMAIN-SUFFIX,atas.net` |
| Platform API, account, licensing and website | `*.atas.net` | `DOMAIN-SUFFIX,atas.net` |
| Indicator descriptions | `cfg.atas.net/indicators/descriptions.json` | Same suffix |
| Articles, tutorials, education and mentor resources | `assets.atas.net` | Same suffix |
| Time synchronization for latency checks | `sntp.atas.net:123` | Exact `DOMAIN` exception to `DIRECT`, before the finance suffix |
| Mac alpha/beta feeds, archives, deltas and DMG | `updates.orderflowtrading.net` | `DOMAIN-SUFFIX,orderflowtrading.net` |
| Legacy indicator/help links | `support.orderflowtrading.ru` | `DOMAIN-SUFFIX,orderflowtrading.ru` |
| Changelog link embedded in the platform | `atas.featurebase.app` | Exact host |
| Embedded news feed | `feed.financialjuice.com` | Exact host |
| Enabled dxFeed delayed quotes and instrument metadata | `get-prod-dxlink-d15m.dxfeed.com`, `tools.dxfeed.com` | `DOMAIN-SUFFIX,dxfeed.com` |
| F2 authentication | `51.178.130.10:6450` | Exact `/32`, `no-resolve` |
| E2 authentication | `142.132.201.231:6450` | Exact `/32`, `no-resolve` |
| R2 authentication | `65.21.32.251:6450` | Exact `/32`, `no-resolve` |
| T2 authentication | `135.181.115.236:6450` | Exact `/32`, `no-resolve` |
| Crypto data | `116.202.174.36:6452` | Exact `/32`, `no-resolve` |
| Crypto Sim | `178.105.188.57:6452` | Exact `/32`, `no-resolve` |
| Authenticated history request | `157.180.79.0:8450` | Exact `/32`, `no-resolve` |
| Authenticated history/cache request | `51.89.6.194:8456` | Exact `/32`, `no-resolve` |
| Crypto data alternate selected after restart | `65.21.228.47:6452` | Exact `/32`, `no-resolve` |
| History/cache alternate selected after restart | `51.89.20.177:8456` | Exact `/32`, `no-resolve` |
| History/cache alternate selected after another restart | `65.108.201.31:8456` | Exact `/32`, `no-resolve` |
| Other data services on already covered hosts | `135.181.115.236:8451`, `51.178.130.10:8451`, `65.21.32.251:8274` | The existing exact `/32` rules also cover these ports |

These are eighteen authored rules: seventeen finance rules and one exact NTP direct
exception, shared by the Loon, Shadowrocket and Surge trees.
The eleven IPs come from ATAS's actual server list and authenticated connection
logs, not a hosting-provider ASN/range.
IP addresses can change; an upgrade or server-list refresh must be audited again.

The Mac's private `[Rule]` section also has seven finance process-and-port fallbacks:

```text
AND,((PROCESS-NAME,ATAS X),(DEST-PORT,6452)),金融加密
```

The same form covers `6214`, `6450`, `6452`, `8274`, `8450`, `8451` and `8456`,
which are the observed ATAS selection/authentication/data protocols. Loon Dashboard
identifies the actual process as `ATAS X`; after loading these rules it showed
`AND` matches for the data connections and Crypto data completed logon. This
handles a newly selected backend without routing unrelated apps or ATAS's entire
HTTPS traffic to finance. Binance HTTPS/WebSocket retains its dedicated policy.
These Mac-specific supplements do not enter the shared iPhone rule lists.
[Loon for Mac's changelog](https://nsloon.app/Loon4Mac/changelog.html) documents
process matching; [logical rules](https://nsloon.app/docs/Rule/logic_rule/) and
[destination ports](https://nsloon.app/docs/Rule/port_rule/) document the combination.

## Other dependencies checked

The local connector configuration references Binance spot/perpetual and testnet
hosts: `api.binance.com`, `fapi.binance.com`, `stream.binance.com:9443`,
`fstream.binance.com`, `stream.binancefuture.com`, `testnet.binancefuture.com`,
and `testnet.binance.vision`. All already reach `Binance` in the generated trees.
Keep that separate ownership instead of forcing the whole ATAS process through
one policy. Other installed exchange/data-provider DLLs do not prove that those
connections are enabled or used.

Public asset metadata references `assets.atas.net`, `atas.net` and `youtu.be`;
the existing YouTube rules cover the latter. Cached help images reference the
shared `cdn.freshdesk.com`. Shared CDN providers are not added wholesale to finance.
Telemetry/promotion failures (`StatisticsA`, `Get ads data error`) are recorded
separately from the fatal authentication timeout; this change does not globally
allow analytics or advertising providers.

## Verification and limits

The Mac app's installed version is `8.0.15.654`; its Developer ID signature is
valid for ATAS SIA (`VHDKF8XLGQ`), and the built-in updater reports that it is up
to date. The downloaded full archive is also verified against the Sparkle
Ed25519 public key embedded in the previously installed app.

HTTP GETs for the four public article/education/tutorial/mentor metadata files
returned 200. The indicator-description request failed its TLS handshake on the
initial direct route and returned 200 after the finance route was loaded.
Authentication attempts to E2 and T2 timed out before the literal-IP rules were
added; after they were loaded the log recorded `User successfully logged in`,
and the main workspace opened. Binance, ATAS Sim and dxFeed connected. The
post-login audit then caught four additional raw data IPs: Crypto data and Crypto
Sim had still timed out on the default path. After the complete data rules were
loaded, both finished logon and all five enabled connections showed `Connected`.
The SOLUSDT 30-minute footprint chart displayed price, volume and delta data.

The vendor NTP host timed out on the finance proxy. An exact direct exception
returned a valid 48-byte UDP/123 reply with less than one second of clock difference.
Apple and Cloudflare time servers also replied in the comparison test. The
[official Common Settings documentation](https://help.atas.net/en/support/solutions/articles/72000602625-common-settings)
identifies NTP as the clock source for latency checks. The original vendor NTP
endpoint remains configured in ATAS.

An ordinary probe succeeding did not establish startup recovery: the ATAS NTP
initializer still timed out. The Mac now pairs `[General] real-ip = sntp.atas.net`
with `AND,((PROCESS-NAME,ATAS X),(DEST-PORT,123)),DIRECT`. Dashboard showed that
real DNS answers become literal `188.245.148.115:123` requests and fall to FINAL
without the process/port exception. The pair avoids Fake-IP endpoint handling
and ensures the actual ATAS UDP socket stays direct even without a domain match.
That current DNS IP is not pinned in the public finance list or routed wholesale.
[Loon's General documentation](https://nsloon.app/en/docs/General/)
documents `real-ip`. This is eight additional Mac rules, twenty-six ATAS rules
in total, while preserving the existing private network exceptions.

Final restart verification: ATAS logged in at 15:13:52 UTC, all five enabled
connections reached `Connected`, and ES history snapshots returned at 15:14:30
and 15:14:33. The native ATAS process received three 48-byte NTP replies at
15:14:11 through the process/123 direct rule. The 30-second initialization
timeout did not recur in the final startup, checked beyond that timeout window.
SOLUSDT's 30-minute footprint, volume and delta data were visible and updated.

Validation: 391 pytest tests passed; all three generated trees passed their
invariant checks; Shadowrocket and Surge config skeletons passed; public artifact
and new-file secret scans passed. The server/domain coverage audit returned no
missing endpoints.

The native Loon `Replace and Keep Nodes & CA` import duplicated static nodes and
chains. Reloading the original nodes/CA verbatim with the new rules using `Full
Cover` restored 358 nodes and passed policy-reference, inline-rule and WireGuard
checks. Finance and Binance still select the user's Taiwan group; its `url-test`
node can change automatically. The full local-config validator retains three
pre-existing complaints about the absent optional `Ads-Reject-Heavy` subscription;
this repair does not enable that subscription.

The audit below detects a newly advertised or logged public server IP that has
no reviewed finance rule. It reads the server cache, vendor URLs and log endpoints;
it does not read saved credentials. A passing audit establishes offline coverage,
not a successful login or market-data subscription.

```sh
python3 tools/audit_atas_routes.py
python3 -m pytest tests/test_routing_safety.py tests/test_validate_config.py
```

[ATAS login instructions](https://help.atas.net/en/support/solutions/articles/72000602246-installing-and-running-the-platform)
describe automatic/manual server selection. [Loon's rule documentation](https://nsloon.app/docs/Rule/)
distinguishes domain and IP matching. Coverage is verified for the server cache,
installed vendor URLs and endpoints observed in this workspace. Other unused
connectors and future server IPs still require an actual connection and a fresh
audit.
