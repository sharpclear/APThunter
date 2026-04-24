// 域名属性分析相关接口

// WHOIS 信息接口
export interface WhoisInfo {
  domain: string
  registrar?: string
  registrationDate?: string
  expirationDate?: string
  updatedDate?: string
  nameServers?: string[]
  registrant?: {
    name?: string
    organization?: string
    email?: string
    phone?: string
    country?: string
  }
  admin?: {
    name?: string
    organization?: string
    email?: string
    phone?: string
  }
  tech?: {
    name?: string
    organization?: string
    email?: string
    phone?: string
  }
  status?: string[]
  raw?: string
}

// DNS 记录接口
export interface DnsRecord {
  type: string
  name: string
  value: string
  ttl?: number
  priority?: number
}

export interface DnsInfo {
  domain: string
  records: DnsRecord[]
  aRecords?: DnsRecord[]
  aaaaRecords?: DnsRecord[]
  cnameRecords?: DnsRecord[]
  mxRecords?: DnsRecord[]
  txtRecords?: DnsRecord[]
  nsRecords?: DnsRecord[]
  soaRecord?: DnsRecord
}

// 证书信息接口
export interface CertificateInfo {
  domain: string
  issuer?: {
    commonName?: string
    organization?: string
    country?: string
  }
  subject?: {
    commonName?: string
    organization?: string
    country?: string
  }
  validity?: {
    notBefore?: string
    notAfter?: string
    daysRemaining?: number
  }
  algorithm?: string
  keySize?: number
  serialNumber?: string
  fingerprint?: string
  sanNames?: string[]
  isExpired?: boolean
  isSelfSigned?: boolean
}

// 域名属性分析完整信息
export interface DomainAttributes {
  domain: string
  whois?: WhoisInfo
  dns?: DnsInfo
  certificate?: CertificateInfo
  queryTime?: string
}

// 查询参数
export interface QueryDomainParams {
  domain: string
}

// 查询域名属性
export async function queryDomainAttributesApi(params: QueryDomainParams) {
  return usePost<DomainAttributes, QueryDomainParams>('/domain/attributes', params, {
    loading: true,
  })
}

// 单独查询 WHOIS 信息
export async function queryWhoisApi(params: QueryDomainParams) {
  return usePost<WhoisInfo, QueryDomainParams>('/domain/whois', params, {
    loading: true,
  })
}

// 单独查询 DNS 信息
export async function queryDnsApi(params: QueryDomainParams) {
  return usePost<DnsInfo, QueryDomainParams>('/domain/dns', params, {
    loading: true,
  })
}

// 单独查询证书信息
export async function queryCertificateApi(params: QueryDomainParams) {
  return usePost<CertificateInfo, QueryDomainParams>('/domain/certificate', params, {
    loading: true,
  })
}

