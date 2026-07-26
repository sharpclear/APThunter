# 域名 APT 归因模块

该目录将 APT2 的历史图谱归因和实时基础设施补全重构为可直接导入的模块。
运行时不执行外部 Python 脚本、不调用 OpenCTI，也不向历史图谱写入候选域名。

## 调用

系统接口为 `POST /api/domain-attribution`：

```json
{
  "domains": ["example.org"],
  "realtime_enrichment": false,
  "include_infrastructure": true
}
```

`realtime_enrichment=false` 时只读取历史图谱，不发出网络请求。检测页面的
“归因到组织”默认不勾选；勾选后只对检测结果中的恶意/仿冒域名传入
`realtime_enrichment=true`。

## 实时补全字段

字段名、归一化规则和哈希输入与 APT2 的基础设施图谱节点保持一致：

- 域名：`domain`、`registered_domain`
- DNS：`ips`、`dns_records`（类型、值、TTL、MX 优先级）、
  `nameservers`、`mailservers`、`cname_targets`、`soa_mnames`、
  `soa_rnames`
- IP 情报：`asns`（ASN、组织、国家）
- RDAP：`registrar`、`registrar_normalized`、`rdap_created`、
  `rdap_updated`、`rdap_expires`、`rdap_statuses`、
  `registrant_identity_sha256`、`registrant_identity_verified`、
  `contact_email_domains`、`uses_privacy_proxy`
- 证书/CT/TLS：`certificates`（证书 SHA256、issuer、subject、
  有效期、序列号、签名算法、公钥类型/长度、SPKI SHA256、过期/自签名、
  观测时间、证书域名）和 `tls_connections`（连接 IP、TLS 版本、
  cipher、ALPN）
- Web：`http_probes`（scheme、状态码、最终 URL、跳转链、Content-Type、
  长度/截断状态、采集时间、标题、正文摘要、HTML/正文/DOM 哈希、
  generator、响应头指纹、Cookie 名集合、JS/CSS 资源、外部资源主机及集合
  哈希、favicon URL/内容哈希、表单 action/主机、统计跟踪 ID）
- 派生复用指纹：`dns_record_set_sha256`、`ip_set_sha256`、
  `ipv4_prefixes_24`、`ipv6_prefixes_48`、`nameserver_set_sha256`、
  `tls_fingerprint_sha256`、DNS TTL 统计、注册/证书时间间隔、
  `snapshot_hashes`、`snapshot_status`
- 采集状态：`provider_status`、`collection_errors`

这些字段会转换为历史图谱中的 `IP`、`ASN`、`CertificateSPKI`、
`DNSRecordSetHash`、`WhoisIdentityHash`、`HTMLHash`、`FaviconHash`、
`TrackingID` 等节点类型，仅作为本次归因的临时起始证据。

## 实时提供方

可配置提供方为 `dns`、`dnsrecords`、`rdap`、`tls`、`ct`、`ipintel`
和 `web`。其中 CT 使用 crt.sh，IP 情报使用 ipwho.is。每个提供方都有独立
环境变量开关，统一受 `APT_ATTRIBUTION_REALTIME_ALLOWED` 控制。
