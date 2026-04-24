"""
组织画像API
提供APT组织的列表、详情、搜索等服务
"""
from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from sqlalchemy import text
from typing import Optional
import json
import logging
from app.db.session import engine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard/org-profile", tags=["organization-profile"])


@router.get("/list")
def list_organizations(
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页数量"),
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
                where_clauses.append("(name LIKE :keyword OR description LIKE :keyword)")
                params["keyword"] = f"%{keyword}%"
            
            where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
            
            # 查询总数
            count_result = conn.execute(
                text(f"SELECT COUNT(*) FROM apt_organizations WHERE {where_sql}"),
                {k: v for k, v in params.items() if k not in ["offset", "limit"]}
            ).scalar()
            
            # 查询数据
            results = conn.execute(
                text(f"""
                    SELECT id, name, alias, description, ioc_count, event_count, 
                           update_time, region, origin, target_countries, 
                           target_industries, previous_domains, vps_providers
                    FROM apt_organizations
                    WHERE {where_sql}
                    ORDER BY COALESCE(update_time, '1970-01-01') DESC, id DESC
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
                    'iocCount': org.get('ioc_count'),
                    'eventCount': org.get('event_count'),
                    'updateTime': org['update_time'].strftime('%Y-%m-%d') if org.get('update_time') and hasattr(org['update_time'], 'strftime') else (str(org['update_time']) if org.get('update_time') else None),
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
                    SELECT id, name, alias, description, ioc_count, event_count, 
                           update_time, region, origin, target_countries, 
                           target_industries, previous_domains, vps_providers,
                           created_at, updated_at
                    FROM apt_organizations
                    WHERE id = :org_id
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
                'iocCount': org_data.get('ioc_count'),
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
                recent_events.append(event_formatted)
            
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
