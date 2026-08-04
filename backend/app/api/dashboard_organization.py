"""
组织画像API
提供APT组织的列表、详情、搜索等服务
"""
from fastapi import APIRouter, HTTPException, Query, Response
from sqlalchemy import text
from typing import Optional
from datetime import datetime
from zoneinfo import ZoneInfo
from urllib.parse import quote
import csv
import io
import json
import logging
from app.db.session import engine
from app.services.apt_event_text import normalize_apt_event_record

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard/org-profile", tags=["organization-profile"])


def _format_export_list(value) -> str:
    """将 JSON 数组格式化为便于表格软件阅读的竖线分隔文本。"""
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, TypeError, ValueError):
            return value
    if isinstance(value, list):
        return "|".join(str(item) for item in value if item is not None)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _format_export_date(value) -> str:
    if value is None:
        return ""
    if hasattr(value, "strftime"):
        value = value.strftime("%Y-%m-%d")
    else:
        value = str(value)
    # CSV 无法保存列宽；以 Excel 文本公式输出，避免日期列宽不足时显示 ####。
    return f'="{value}"'


@router.get("/{org_id}/export")
def export_organization_csv(org_id: int):
    """导出单个 APT 组织的基本信息 CSV。"""
    with engine.connect() as conn:
        organization = conn.execute(
            text("""
                SELECT o.name AS organization_name,
                       o.alias AS aliases,
                       o.origin,
                       o.region,
                       o.target_countries,
                       o.target_industries,
                       o.description,
                       (
                           SELECT MIN(e.event_date)
                           FROM apt_events e
                           WHERE e.organization_id = o.id
                       ) AS first_event_date,
                       (
                           SELECT MAX(e.event_date)
                           FROM apt_events e
                           WHERE e.organization_id = o.id
                       ) AS latest_event_date,
                       (
                           SELECT COUNT(*)
                           FROM domains d
                           WHERE d.organization_id = o.id
                             AND d.is_malicious = 1
                       ) AS malicious_domain_count,
                       (
                           SELECT COUNT(*)
                           FROM apt_events e
                           WHERE e.organization_id = o.id
                       ) AS event_count,
                       o.update_time
                FROM apt_organizations o
                WHERE o.id = :org_id
            """),
            {"org_id": org_id},
        ).mappings().fetchone()

        if not organization:
            raise HTTPException(status_code=404, detail="组织不存在")

    exported_at = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
    basic_info = {
        "organization_name": organization["organization_name"] or "",
        "aliases": _format_export_list(organization["aliases"]),
        "origin": organization["origin"] or "",
        "region": organization["region"] or "",
        "target_countries": _format_export_list(organization["target_countries"]),
        "target_industries": _format_export_list(organization["target_industries"]),
        "description": organization["description"] or "",
        "first_event_date": _format_export_date(organization["first_event_date"]),
        "latest_event_date": _format_export_date(organization["latest_event_date"]),
        "malicious_domain_count": int(organization["malicious_domain_count"] or 0),
        "event_count": int(organization["event_count"] or 0),
        "update_time": _format_export_date(organization["update_time"]),
        "exported_at": f'="{exported_at}"',
    }

    columns = [
        ("组织名称", "organization_name"),
        ("别名", "aliases"),
        ("来源国家/地区", "origin"),
        ("所属区域", "region"),
        ("目标国家", "target_countries"),
        ("目标行业", "target_industries"),
        ("组织描述", "description"),
        ("最早事件时间", "first_event_date"),
        ("最近事件时间", "latest_event_date"),
        ("相关恶意域名总数", "malicious_domain_count"),
        ("相关事件数", "event_count"),
        ("更新时间", "update_time"),
        ("导出时间", "exported_at"),
    ]
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow([label for label, _ in columns])
    writer.writerow([basic_info[key] for _, key in columns])

    filename = f"{organization['organization_name']}.csv"
    encoded_filename = quote(filename, safe="")
    return Response(
        content=("\ufeff" + output.getvalue()).encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="organization.csv"; '
                f"filename*=UTF-8''{encoded_filename}"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/list")
def list_organizations(
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=200, description="每页数量"),
    region: Optional[str] = Query(None, description="地区筛选"),
    keyword: Optional[str] = Query(None, description="关键词搜索")
):
    """获取APT组织列表"""
    try:
        with engine.connect() as conn:
            # 构建查询条件
            where_clauses = []
            params = {"offset": (page - 1) * page_size, "limit": page_size}
            
            if region:
                where_clauses.append("region = :region")
                params["region"] = region
            
            if keyword:
                where_clauses.append("(name LIKE :keyword_like OR JSON_SEARCH(alias, 'one', :keyword_like) IS NOT NULL)")
                params["keyword_like"] = f"%{keyword}%"
            
            where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
            
            # 查询总数
            count_result = conn.execute(
                text(f"SELECT COUNT(*) FROM apt_organizations WHERE {where_sql}"),
                {k: v for k, v in params.items() if k not in ["offset", "limit"]}
            ).scalar()
            
            # 查询数据
            results = conn.execute(
                text(f"""
                          SELECT o.id, o.name, o.alias, o.description,
                              COALESCE(md.malicious_domain_count, 0) AS malicious_domain_count,
                              o.event_count, o.update_time,
                              (
                               SELECT MAX(event_date)
                               FROM apt_events e
                               WHERE e.organization_id = o.id
                              ) AS latest_event_date,
                              o.region, o.origin, o.target_countries,
                              o.target_industries, o.previous_domains, o.vps_providers
                    FROM apt_organizations o
                    LEFT JOIN (
                        SELECT organization_id, COUNT(*) AS malicious_domain_count
                        FROM domains
                        WHERE is_malicious = 1
                          AND organization_id IS NOT NULL
                        GROUP BY organization_id
                    ) md ON md.organization_id = o.id
                    WHERE {where_sql}
                    ORDER BY latest_event_date IS NULL ASC, latest_event_date DESC, o.id ASC
                    LIMIT :limit OFFSET :offset
                """),
                params
            ).mappings().all()
            
            # 转换日期对象为字符串，并将字段名转换为驼峰命名
            import json
            organizations = []
            for row in results:
                org = dict(row)
                
                # 辅助函数：解析JSON字段（MySQL的JSON字段以字符串形式返回）
                def parse_json_field(field_value):
                    if field_value is None:
                        return None
                    # 如果是字符串，尝试解析
                    if isinstance(field_value, str):
                        try:
                            return json.loads(field_value)
                        except (json.JSONDecodeError, TypeError, ValueError):
                            return field_value
                    # 如果已经是list或dict，直接返回
                    elif isinstance(field_value, (list, dict)):
                        return field_value
                    return field_value
                
                # 转换字段名为驼峰命名，并解析JSON字段
                org_formatted = {
                    'id': org.get('id'),
                    'name': org.get('name'),
                    'alias': parse_json_field(org.get('alias')),
                    'description': org.get('description'),
                    'maliciousDomainCount': org.get('malicious_domain_count'),
                    'iocCount': org.get('malicious_domain_count'),
                    'eventCount': org.get('event_count'),
                    'updateTime': org['update_time'].strftime('%Y-%m-%d') if org.get('update_time') and hasattr(org['update_time'], 'strftime') else (str(org['update_time']) if org.get('update_time') else None),
                    'latestEventDate': org['latest_event_date'].strftime('%Y-%m-%d') if org.get('latest_event_date') and hasattr(org['latest_event_date'], 'strftime') else (str(org['latest_event_date']) if org.get('latest_event_date') else None),
                    'region': org.get('region'),
                    'origin': org.get('origin'),
                    'targetCountries': parse_json_field(org.get('target_countries')),
                    'targetIndustries': parse_json_field(org.get('target_industries')),
                    'previousDomains': parse_json_field(org.get('previous_domains')),
                    'vpsProviders': parse_json_field(org.get('vps_providers'))
                }
                organizations.append(org_formatted)
            
            # 调试输出第一个组织的数据类型
            if organizations:
                logger.info(f"First org vpsProviders type: {type(organizations[0].get('vpsProviders'))}")
                logger.info(f"First org vpsProviders value: {organizations[0].get('vpsProviders')}")
            
            return {
                "code": 200,
                "msg": "查询成功",
                "data": {
                    "list": organizations,
                    "total": count_result,
                    "page": page,
                    "pageSize": page_size
                }
            }
            
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=f"查询失败: {str(e)}")


@router.get("/{org_id}")
def get_organization_detail(org_id: int):
    """获取组织详情"""
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT o.id, o.name, o.alias, o.description,
                           (
                               SELECT COUNT(*)
                               FROM domains d
                               WHERE d.organization_id = o.id
                                 AND d.is_malicious = 1
                           ) AS malicious_domain_count,
                           o.event_count, o.update_time, o.region, o.origin,
                           o.target_countries, o.target_industries,
                           o.previous_domains, o.vps_providers,
                           o.created_at, o.updated_at
                    FROM apt_organizations o
                    WHERE o.id = :org_id
                """),
                {"org_id": org_id}
            ).mappings().fetchone()
            
            if not result:
                from fastapi import HTTPException
                raise HTTPException(status_code=404, detail="组织不存在")
            
            import json
            org_data = dict(result)
            
            # 辅助函数：解析JSON字段（MySQL的JSON字段以字符串形式返回）
            def parse_json_field(field_value):
                if field_value is None:
                    return None
                # 如果是字符串，尝试解析
                if isinstance(field_value, str):
                    try:
                        return json.loads(field_value)
                    except (json.JSONDecodeError, TypeError, ValueError):
                        return field_value
                # 如果已经是list或dict，直接返回
                elif isinstance(field_value, (list, dict)):
                    return field_value
                return field_value
            
            # 转换为驼峰命名并格式化日期
            org_formatted = {
                'id': org_data.get('id'),
                'name': org_data.get('name'),
                'alias': parse_json_field(org_data.get('alias')),
                'description': org_data.get('description'),
                'maliciousDomainCount': org_data.get('malicious_domain_count'),
                'iocCount': org_data.get('malicious_domain_count'),
                'eventCount': org_data.get('event_count'),
                'updateTime': org_data['update_time'].strftime('%Y-%m-%d') if org_data.get('update_time') and hasattr(org_data['update_time'], 'strftime') else (str(org_data['update_time']) if org_data.get('update_time') else None),
                'region': org_data.get('region'),
                'origin': org_data.get('origin'),
                'targetCountries': parse_json_field(org_data.get('target_countries')),
                'targetIndustries': parse_json_field(org_data.get('target_industries')),
                'previousDomains': parse_json_field(org_data.get('previous_domains')),
                'vpsProviders': parse_json_field(org_data.get('vps_providers')),
                'createdAt': org_data['created_at'].strftime('%Y-%m-%d %H:%M:%S') if org_data.get('created_at') and hasattr(org_data['created_at'], 'strftime') else (str(org_data['created_at']) if org_data.get('created_at') else None),
                'updatedAt': org_data['updated_at'].strftime('%Y-%m-%d %H:%M:%S') if org_data.get('updated_at') and hasattr(org_data['updated_at'], 'strftime') else (str(org_data['updated_at']) if org_data.get('updated_at') else None),
            }
            
            # 查询该组织的相关事件
            events = conn.execute(
                text("""
                    SELECT id, event_date, title, description, event_type, region, severity
                    FROM apt_events
                    WHERE organization_id = :org_id
                    ORDER BY event_date DESC
                    LIMIT 50
                """),
                {"org_id": org_id}
            ).mappings().all()
            
            # 转换事件日期为驼峰命名
            recent_events = []
            for e in events:
                event = dict(e)
                event_formatted = {
                    'id': event.get('id'),
                    'eventDate': event['event_date'].strftime('%Y-%m-%d') if event.get('event_date') and hasattr(event['event_date'], 'strftime') else (str(event['event_date']) if event.get('event_date') else None),
                    'title': event.get('title'),
                    'description': event.get('description'),
                    'eventType': event.get('event_type'),
                    'region': event.get('region'),
                    'severity': event.get('severity')
                }
                recent_events.append(normalize_apt_event_record(event_formatted))
            
            org_formatted["recentEvents"] = recent_events
            
            return {
                "code": 200,
                "msg": "查询成功",
                "data": org_formatted
            }
            
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=f"查询失败: {str(e)}")


@router.get("/regions")
def get_regions():
    """获取所有地区列表及组织数量"""
    try:
        with engine.connect() as conn:
            results = conn.execute(
                text("""
                    SELECT region, COUNT(*) as count
                    FROM apt_organizations
                    WHERE region IS NOT NULL AND region != ''
                    GROUP BY region
                    ORDER BY count DESC
                """)
            ).mappings().all()
            
            return {
                "code": 200,
                "msg": "查询成功",
                "data": [dict(r) for r in results]
            }
            
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=f"查询失败: {str(e)}")
