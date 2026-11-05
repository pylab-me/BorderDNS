# BorderDNS

BorderDNS is a high-performance DNS runtime with a **facts-aware domain governance loop**.

---

## 1. Product Identity

BorderDNS consists of:

```text
DNS Runtime
    +
Facts-aware Domain Governance Loop
```


## Data Flow

```mermaid 
flowchart LR
  admin("Read-only admin snapshots")
  authority["Authoritative DNS servers"]
  backend("Pipeline backend: forwarding / recursive")
  cache[("Route-scoped answer cache (memory)")]
  client["DNS client"]
  diagnostic("Gated explicit DNS diagnostic POST")
  facts[("Facts JSONL and manifest")]
  ingress("Authenticated peer observation ingress")
  latency("Location-scoped latency worker")
  maintenance("Governance maintenance")
  measurements[("Latency read model (memory)")]
  observe("Bounded TLS and third-party observation")
  operator["Operator / dashboard"]
  peer["Authenticated observer peers"]
  recent[("Bounded recent facts read model")]
  reduce("Reducer + ordered local evidence worker")
  refresh("Bounded cache refresh")
  resolve("Shared DNS pipeline: parse, route, cache, shape")
  serve("Transport admission and response encoding")
  state[("Governance state (memory + durable journal)")]
  targets["TLS and TCP probe targets"]
  telemetry[("Typed metrics and runtime feedback")]
  upstream["Forward DNS upstreams"]
  writer("Batched cold-path fact writer")
  client -->|"DNS request bytes"| serve
  serve -->|"DNS response bytes; UDP size handling"| client
  upstream -->|"Forward DNS response"| backend
  backend -->|"Iterative DNS query via resolver"| authority
  authority -->|"Authoritative DNS response"| backend
  resolve -->|"EvidenceEnvelope via bounded try_send"| reduce
  resolve -->|"ObservationTask via bounded try_send"| observe
  observe -->|"Bounded TLS identity probe"| targets
  targets -->|"TLS identity result"| observe
  observe -->|"Authenticated snapshot fetch"| peer
  peer -->|"Validated third-party snapshot"| observe
  observe -->|"Normalized TLS or third-party evidence"| reduce
  serve -->|"Admitted request and RequestMeta"| resolve
  reduce -->|"Reducer-owned state transition and journal"| state
  state -->|"Versioned state"| reduce
  reduce -->|"BorderDnsFactEvent via bounded queue"| writer
  writer -->|"Batch append outside request path"| facts
  writer -->|"Projected recent facts; not durable receipt"| recent
  resolve -->|"Eligible LatencyProbeBatch via bounded try_send"| latency
  latency -->|"TCP connect to location-eligible IP"| targets
  targets -->|"Connect latency or failure"| latency
  latency -->|"Successful latency samples"| measurements
  measurements -->|"Answer ordering only; never route authority"| resolve
  resolve -->|"PipelineResponse and EDNS budget"| serve
  resolve -->|"Typed execution metrics and feedback"| telemetry
  operator -->|"Snapshot GET and filters"| admin
  state -->|"Governance snapshot"| admin
  cache -->|"Cache snapshot"| admin
  telemetry -->|"Metrics and feedback snapshot"| admin
  recent -->|"Retained recent fact rows"| admin
  admin -->|"Read-only dashboard DTOs"| operator
  operator -->|"Loopback gated POST domain and qtype"| diagnostic
  diagnostic -->|"Canonical FQDN; private + global admission"| resolve
  resolve -->|"Served result and QueryExecution"| diagnostic
  state -->|"Recorded attribution for future query route"| resolve
  diagnostic -->|"Diagnostic DNS result or HTTP error"| operator
  peer -->|"Authenticated observation request"| ingress
  ingress -->|"Validated evidence via shared bounded queue"| reduce
  state -->|"Lifecycle candidates"| maintenance
  maintenance -->|"MaintenanceEvidence"| reduce
  cache -->|"Due refresh candidates"| refresh
  refresh -->|"Background refresh through pipeline-owned API"| resolve
  resolve -->|"Route-scoped lookup and insert"| cache
  cache -->|"Cached DNS answer or miss"| resolve
  resolve -->|"Cache miss; frozen route and query"| backend
  backend -->|"ResolutionResponse with explicit source"| resolve
  backend -->|"Forward DNS query; selected group(s)"| upstream
```

---

## UML Components

```mermaid
flowchart LR
  border_dns_cache["border-dns-cache"]
  border_dns_cli["border-dns-cli"]
  border_dns_config["border-dns-config"]
  border_dns_domain_knowledge["border-dns-domain-knowledge"]
  border_dns_facts["border-dns-facts"]
  border_dns_geoip["border-dns-geoip"]
  border_dns_governance["border-dns-governance"]
  border_dns_metrics["border-dns-metrics"]
  border_dns_peers["border-dns-peers"]
  border_dns_pipeline["border-dns-pipeline"]
  border_dns_platform["border-dns-platform"]
  border_dns_probes["border-dns-probes"]
  border_dns_route_policy["border-dns-route-policy"]
  border_dns_runtime["border-dns-runtime"]
  border_dns_upstream["border-dns-upstream"]
  dns_protocol["dns-protocol"]
  dns_resolver["dns-resolver"]
  dns_transport["dns-transport"]
  dns_types["dns-types"]
  doq_client["doq-client"]
  doq_core["doq-core"]
  doq_crypto["doq-crypto"]
  doq_crypto_rustls["doq-crypto-rustls"]
  doq_dispatch["doq-dispatch"]
  doq_io["doq-io"]
  doq_protection["doq-protection"]
  doq_server["doq-server"]
  border_dns_cache -->|"border-dns-metrics"| border_dns_metrics
  border_dns_cache -->|"dns-types"| dns_types
  border_dns_cli -->|"dns-types"| dns_types
  border_dns_config -->|"dns-types"| dns_types
  border_dns_config -->|"facts"| border_dns_facts
  border_dns_domain_knowledge -->|"dns-types"| dns_types
  border_dns_domain_knowledge -->|"dns-protocol"| dns_protocol
  border_dns_domain_knowledge -->|"runtime-config"| border_dns_config
  border_dns_geoip -->|"dns-types"| dns_types
  border_dns_geoip -->|"border-dns-platform"| border_dns_platform
  border_dns_governance -->|"border-dns-metrics"| border_dns_metrics
  border_dns_governance -->|"facts"| border_dns_facts
  border_dns_cache -->|"dns-protocol"| dns_protocol
  border_dns_metrics -->|"facts"| border_dns_facts
  border_dns_pipeline -->|"border-dns-metrics"| border_dns_metrics
  border_dns_pipeline -->|"dns-types"| dns_types
  border_dns_pipeline -->|"dns-protocol"| dns_protocol
  border_dns_pipeline -->|"dns-transport"| dns_transport
  border_dns_pipeline -->|"runtime-config"| border_dns_config
  border_dns_pipeline -->|"route-cache"| border_dns_cache
  border_dns_pipeline -->|"border-dns-upstream"| border_dns_upstream
  border_dns_pipeline -->|"dns-resolver"| dns_resolver
  border_dns_pipeline -->|"domain-knowledge"| border_dns_domain_knowledge
  border_dns_cache -->|"runtime-config"| border_dns_config
  border_dns_pipeline -->|"geoip"| border_dns_geoip
  border_dns_pipeline -->|"route-policy"| border_dns_route_policy
  border_dns_pipeline -->|"border-dns-governance"| border_dns_governance
  border_dns_pipeline -->|"border-dns-probes"| border_dns_probes
  border_dns_pipeline -->|"facts"| border_dns_facts
  border_dns_probes -->|"dns-types"| dns_types
  border_dns_probes -->|"facts"| border_dns_facts
  doq_client -->|"doq-core"| doq_core
  doq_client -->|"doq-io"| doq_io
  doq_client -->|"doq-crypto-rustls"| doq_crypto_rustls
  border_dns_cli -->|"runtime-config"| border_dns_config
  doq_client -->|"doq-protection"| doq_protection
  doq_crypto_rustls -->|"doq-crypto"| doq_crypto
  doq_protection -->|"doq-crypto"| doq_crypto
  doq_protection -->|"doq-crypto-rustls"| doq_crypto_rustls
  doq_server -->|"doq-core"| doq_core
  doq_server -->|"doq-io"| doq_io
  doq_server -->|"doq-crypto-rustls"| doq_crypto_rustls
  doq_server -->|"doq-protection"| doq_protection
  doq_server -->|"doq-dispatch"| doq_dispatch
  border_dns_route_policy -->|"dns-types"| dns_types
  border_dns_cli -->|"border-dns-runtime"| border_dns_runtime
  border_dns_route_policy -->|"geoip"| border_dns_geoip
  border_dns_route_policy -->|"dns-protocol"| dns_protocol
  border_dns_runtime -->|"border-dns-metrics"| border_dns_metrics
  border_dns_runtime -->|"dns-types"| dns_types
  border_dns_runtime -->|"dns-protocol"| dns_protocol
  border_dns_runtime -->|"dns-transport"| dns_transport
  border_dns_runtime -->|"doq-server"| doq_server
  border_dns_runtime -->|"doq-core"| doq_core
  border_dns_runtime -->|"doq-io"| doq_io
  border_dns_runtime -->|"doq-crypto-rustls"| doq_crypto_rustls
  border_dns_cli -->|"domain-knowledge"| border_dns_domain_knowledge
  border_dns_runtime -->|"runtime-config"| border_dns_config
  border_dns_runtime -->|"route-cache"| border_dns_cache
  border_dns_runtime -->|"border-dns-upstream"| border_dns_upstream
  border_dns_runtime -->|"border-dns-pipeline"| border_dns_pipeline
  border_dns_runtime -->|"border-dns-governance"| border_dns_governance
  border_dns_runtime -->|"domain-knowledge"| border_dns_domain_knowledge
  border_dns_runtime -->|"facts"| border_dns_facts
  border_dns_runtime -->|"geoip"| border_dns_geoip
  border_dns_runtime -->|"border-dns-probes"| border_dns_probes
  border_dns_runtime -->|"border-dns-peers"| border_dns_peers
  border_dns_cli -->|"route-policy"| border_dns_route_policy
  border_dns_upstream -->|"dns-protocol"| dns_protocol
  border_dns_upstream -->|"dns-transport"| dns_transport
  border_dns_upstream -->|"runtime-config"| border_dns_config
  border_dns_upstream -->|"doq-client"| doq_client
  border_dns_upstream -->|"doq-core"| doq_core
  border_dns_upstream -->|"doq-io"| doq_io
  border_dns_upstream -->|"doq-crypto-rustls"| doq_crypto_rustls
  dns_protocol -->|"dns-types"| dns_types
  dns_resolver -->|"dns-types"| dns_types
  dns_resolver -->|"dns-protocol"| dns_protocol
  border_dns_cli -->|"border-dns-governance"| border_dns_governance
  dns_transport -->|"dns-types"| dns_types
  dns_transport -->|"dns-protocol"| dns_protocol
  border_dns_cli -->|"facts"| border_dns_facts
```
