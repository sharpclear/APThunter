"""
域名属性查询API
提供域名的WHOIS、DNS、SSL证书等属性查询服务
"""
from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import text
from typing import Optional
from pydantic import BaseModel

router = APIRouter(prefix="/api/domain", tags=["domain-attributes"])


class DomainQueryRequest(BaseModel):
    domain: str


@router.get("/list")
def get_domain_list():
    """获取数据库中有数据的域名列表（至少有WHOIS、DNS或SSL证书信息之一）"""
    from main import engine
    
    try:
        with engine.connect() as conn:
            results = conn.execute(
                text("""
                    SELECT DISTINCT d.domain_name, d.created_at,
                           (SELECT COUNT(*) FROM whois_info WHERE domain_id = d.id) as has_whois,
                           (SELECT COUNT(*) FROM dns_records WHERE domain_id = d.id) as has_dns,
                           (SELECT COUNT(*) FROM ssl_certificates WHERE domain_id = d.id) as has_ssl
                    FROM domains d
                    WHERE EXISTS (
                        SELECT 1 FROM whois_info WHERE domain_id = d.id
                        UNION
                        SELECT 1 FROM dns_records WHERE domain_id = d.id
                        UNION
                        SELECT 1 FROM ssl_certificates WHERE domain_id = d.id
                    )
                    ORDER BY d.created_at DESC
                """)
            ).fetchall()
            
            domains = []
            for row in results:
                domains.append({
                    "domain": row[0],
                    "createdAt": str(row[1]) if row[1] else None,
                    "hasWhois": row[2] > 0,
                    "hasDns": row[3] > 0,
                    "hasSsl": row[4] > 0
                })
            
            return JSONResponse(content={
                "code": 200,
                "msg": "查询成功",
                "data": domains
            })
            
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"查询失败: {str(e)}", "data": None}
        )


@router.post("/attributes")
def query_domain_attributes(request: DomainQueryRequest = Body(...)):
    """查询域名的完整属性信息（WHOIS + DNS + 证书）"""
    from main import engine
    
    domain = request.domain.strip()
    if not domain:
        return JSONResponse(
            status_code=400,
            content={"code": 400, "msg": "域名不能为空", "data": None}
        )
    
    try:
        with engine.connect() as conn:
            # 查找或创建域名记录
            domain_row = conn.execute(
                text("SELECT id FROM domains WHERE domain_name = :domain"),
                {"domain": domain}
            ).fetchone()
            
            if not domain_row:
                conn.execute(
                    text("INSERT INTO domains (domain_name) VALUES (:domain)"),
                    {"domain": domain}
                )
                conn.commit()
                domain_row = conn.execute(
                    text("SELECT id FROM domains WHERE domain_name = :domain"),
                    {"domain": domain}
                ).fetchone()
            
            domain_id = domain_row[0]
            
            # 查询WHOIS信息
            import json
            whois_data = None
            whois_row = conn.execute(
                text("""
                    SELECT registrar, registration_date, expiration_date, updated_date,
                           name_servers, registrant, admin, tech, status
                    FROM whois_info 
                    WHERE domain_id = :domain_id 
                    ORDER BY query_time DESC LIMIT 1
                """),
                {"domain_id": domain_id}
            ).fetchone()
            
            if whois_row:
                # 辅助函数：解析JSON字段
                def parse_json_field(field_value):
                    if field_value is None:
                        return None
                    if isinstance(field_value, str):
                        try:
                            return json.loads(field_value)
                        except (json.JSONDecodeError, TypeError, ValueError):
                            return field_value
                    return field_value
                
                whois_data = {
                    "domain": domain,
                    "registrar": whois_row[0],
                    "registrationDate": str(whois_row[1]) if whois_row[1] else None,
                    "expirationDate": str(whois_row[2]) if whois_row[2] else None,
                    "updatedDate": str(whois_row[3]) if whois_row[3] else None,
                    "nameServers": parse_json_field(whois_row[4]),
                    "registrant": parse_json_field(whois_row[5]),
                    "admin": parse_json_field(whois_row[6]),
                    "tech": parse_json_field(whois_row[7]),
                    "status": parse_json_field(whois_row[8])
                }
            
            # 查询DNS记录
            dns_records = []
            dns_rows = conn.execute(
                text("""
                    SELECT record_type, record_name, record_value, ttl, priority
                    FROM dns_records 
                    WHERE domain_id = :domain_id
                    ORDER BY record_type, record_name
                """),
                {"domain_id": domain_id}
            ).fetchall()
            
            for row in dns_rows:
                dns_records.append({
                    "type": row[0],
                    "name": row[1],
                    "value": row[2],
                    "ttl": row[3],
                    "priority": row[4]
                })
            
            # 查询SSL证书
            cert_data = None
            cert_row = conn.execute(
                text("""
                    SELECT issuer, subject, not_before, not_after, algorithm, 
                           key_size, serial_number, fingerprint, san_names,
                           is_expired, is_self_signed
                    FROM ssl_certificates 
                    WHERE domain_id = :domain_id 
                    ORDER BY created_at DESC LIMIT 1
                """),
                {"domain_id": domain_id}
            ).fetchone()
            
            if cert_row:
                cert_data = {
                    "domain": domain,
                    "issuer": parse_json_field(cert_row[0]),
                    "subject": parse_json_field(cert_row[1]),
                    "validity": {
                        "notBefore": str(cert_row[2]) if cert_row[2] else None,
                        "notAfter": str(cert_row[3]) if cert_row[3] else None
                    },
                    "algorithm": cert_row[4],
                    "keySize": cert_row[5],
                    "serialNumber": cert_row[6],
                    "fingerprint": cert_row[7],
                    "sanNames": parse_json_field(cert_row[8]),
                    "isExpired": bool(cert_row[9]),
                    "isSelfSigned": bool(cert_row[10])
                }
            
            # 检查是否查询到任何数据
            has_data = whois_data is not None or dns_records or cert_data is not None
            
            if not has_data:
                return JSONResponse(content={
                    "code": 404,
                    "msg": f"未找到域名 {domain} 的相关信息",
                    "data": None
                })
            
            return JSONResponse(content={
                "code": 200,
                "msg": "查询成功",
                "data": {
                    "domain": domain,
                    "whois": whois_data,
                    "dns": {"domain": domain, "records": dns_records} if dns_records else None,
                    "certificate": cert_data,
                    "queryTime": None  # 可以添加当前时间
                }
            })
            
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"查询失败: {str(e)}", "data": None}
        )


@router.post("/whois")
def query_whois(request: DomainQueryRequest = Body(...)):
    """查询域名WHOIS信息"""
    from main import engine
    
    domain = request.domain.strip()
    if not domain:
        return JSONResponse(
            status_code=400,
            content={"code": 400, "msg": "域名不能为空", "data": None}
        )
    
    try:
        import json
        
        # 辅助函数：解析JSON字段
        def parse_json_field(field_value):
            if field_value is None:
                return None
            if isinstance(field_value, str):
                try:
                    return json.loads(field_value)
                except (json.JSONDecodeError, TypeError, ValueError):
                    return field_value
            return field_value
        
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT w.registrar, w.registration_date, w.expiration_date, w.updated_date,
                           w.name_servers, w.registrant, w.admin, w.tech, w.status
                    FROM whois_info w
                    JOIN domains d ON w.domain_id = d.id
                    WHERE d.domain_name = :domain
                    ORDER BY w.query_time DESC LIMIT 1
                """),
                {"domain": domain}
            ).fetchone()
            
            if not result:
                return JSONResponse(content={
                    "code": 404,
                    "msg": f"未找到域名 {domain} 的WHOIS信息",
                    "data": None
                })
            
            data = {
                "domain": domain,
                "registrar": result[0],
                "registrationDate": str(result[1]) if result[1] else None,
                "expirationDate": str(result[2]) if result[2] else None,
                "updatedDate": str(result[3]) if result[3] else None,
                "nameServers": parse_json_field(result[4]),
                "registrant": parse_json_field(result[5]),
                "admin": parse_json_field(result[6]),
                "tech": parse_json_field(result[7]),
                "status": parse_json_field(result[8])
            }
            
            return JSONResponse(content={
                "code": 200,
                "msg": "查询成功",
                "data": data
            })
            
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"查询失败: {str(e)}", "data": None}
        )


@router.post("/dns")
def query_dns(request: DomainQueryRequest = Body(...)):
    """查询域名DNS记录"""
    from main import engine
    
    domain = request.domain.strip()
    if not domain:
        return JSONResponse(
            status_code=400,
            content={"code": 400, "msg": "域名不能为空", "data": None}
        )
    
    try:
        with engine.connect() as conn:
            results = conn.execute(
                text("""
                    SELECT r.record_type, r.record_name, r.record_value, r.ttl, r.priority
                    FROM dns_records r
                    JOIN domains d ON r.domain_id = d.id
                    WHERE d.domain_name = :domain
                    ORDER BY r.record_type, r.record_name
                """),
                {"domain": domain}
            ).fetchall()
            
            records = []
            for row in results:
                records.append({
                    "type": row[0],
                    "name": row[1],
                    "value": row[2],
                    "ttl": row[3],
                    "priority": row[4]
                })
            
            return JSONResponse(content={
                "code": 200,
                "msg": "查询成功",
                "data": {
                    "domain": domain,
                    "records": records
                }
            })
            
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"查询失败: {str(e)}", "data": None}
        )


@router.post("/certificate")
def query_certificate(request: DomainQueryRequest = Body(...)):
    """查询域名SSL证书信息"""
    from main import engine
    
    domain = request.domain.strip()
    if not domain:
        return JSONResponse(
            status_code=400,
            content={"code": 400, "msg": "域名不能为空", "data": None}
        )
    
    try:
        import json
        
        # 辅助函数：解析JSON字段
        def parse_json_field(field_value):
            if field_value is None:
                return None
            if isinstance(field_value, str):
                try:
                    return json.loads(field_value)
                except (json.JSONDecodeError, TypeError, ValueError):
                    return field_value
            return field_value
        
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT c.issuer, c.subject, c.not_before, c.not_after, c.algorithm, 
                           c.key_size, c.serial_number, c.fingerprint, c.san_names,
                           c.is_expired, c.is_self_signed
                    FROM ssl_certificates c
                    JOIN domains d ON c.domain_id = d.id
                    WHERE d.domain_name = :domain
                    ORDER BY c.created_at DESC LIMIT 1
                """),
                {"domain": domain}
            ).fetchone()
            
            if not result:
                return JSONResponse(content={
                    "code": 200,
                    "msg": "未找到证书信息",
                    "data": None
                })
            
            data = {
                "domain": domain,
                "issuer": parse_json_field(result[0]),
                "subject": parse_json_field(result[1]),
                "validity": {
                    "notBefore": str(result[2]) if result[2] else None,
                    "notAfter": str(result[3]) if result[3] else None
                },
                "algorithm": result[4],
                "keySize": result[5],
                "serialNumber": result[6],
                "fingerprint": result[7],
                "sanNames": parse_json_field(result[8]),
                "isExpired": bool(result[9]),
                "isSelfSigned": bool(result[10])
            }
            
            return JSONResponse(content={
                "code": 200,
                "msg": "查询成功",
                "data": data
            })
            
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"查询失败: {str(e)}", "data": None}
        )
