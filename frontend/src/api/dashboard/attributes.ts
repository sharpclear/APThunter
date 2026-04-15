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
	organizationId?: number | null
	organizationName?: string | null
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
	return usePost<DomainAttributes, QueryDomainParams>('/api/domain/attributes', params, {
		loading: true,
	})
}

// 单独查询 WHOIS 信息
export async function queryWhoisApi(params: QueryDomainParams) {
	return usePost<WhoisInfo, QueryDomainParams>('/api/domain/whois', params, {
		loading: true,
	})
}

// 单独查询 DNS 信息
export async function queryDnsApi(params: QueryDomainParams) {
	return usePost<DnsInfo, QueryDomainParams>('/api/domain/dns', params, {
		loading: true,
	})
}

// 单独查询证书信息
export async function queryCertificateApi(params: QueryDomainParams) {
	return usePost<CertificateInfo, QueryDomainParams>('/api/domain/certificate', params, {
		loading: true,
	})
}

// 域名列表项接口
export interface DomainListItem {
	domain: string
	createdAt?: string
	organizationId?: number | null
	organizationName?: string | null
	isMalicious?: boolean
	hasWhois?: boolean
	hasDns?: boolean
	hasSsl?: boolean
}

// 获取所有域名列表
export async function getDomainListApi() {
	return useGet<DomainListItem[]>('/api/domain/list')
}

// ==================== 实时查询接口 ====================

// 实时查询请求参数
export interface LookupDomainParams {
	domain: string
	save?: boolean // 是否保存到数据库
}

// 实时查询结果
export interface LookupResult {
	domain: string
	whois?: WhoisInfo
	dns?: DnsInfo
	certificate?: CertificateInfo
	errors: string[]
	queryTime: string
	saved?: boolean
}

// 实时查询所有信息（WHOIS + DNS + SSL）
export async function lookupDomainAllApi(params: LookupDomainParams) {
	return usePost<LookupResult, LookupDomainParams>('/api/domain/lookup/all', params, {
		loading: true,
	})
}

// 单独实时查询 WHOIS
export async function lookupWhoisOnlyApi(params: LookupDomainParams) {
	return usePost<WhoisInfo, LookupDomainParams>('/api/domain/lookup/whois', params, {
		loading: true,
	})
}

// 单独实时查询 DNS
export async function lookupDnsOnlyApi(params: LookupDomainParams) {
	return usePost<DnsInfo, LookupDomainParams>('/api/domain/lookup/dns', params, {
		loading: true,
	})
}

// 单独实时查询 SSL 证书
export async function lookupSslOnlyApi(params: LookupDomainParams) {
	return usePost<CertificateInfo, LookupDomainParams>('/api/domain/lookup/ssl', params, {
		loading: true,
	})
}
