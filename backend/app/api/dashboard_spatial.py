"""
时空分布API
提供APT事件的时间和空间分布数据
"""
from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from sqlalchemy import text
from typing import Optional
from datetime import datetime, timedelta
from decimal import Decimal

router = APIRouter(prefix="/api/dashboard/spatio-temporal", tags=["spatio-temporal"])


def convert_to_json_serializable(obj):
    """转换对象为JSON可序列化的类型"""
    if hasattr(obj, 'strftime'):  # datetime/date
        return obj.strftime('%Y-%m-%d %H:%M:%S') if hasattr(obj, 'hour') else obj.strftime('%Y-%m-%d')
    elif isinstance(obj, Decimal):
        return float(obj)
    return obj


@router.get("/events")
def get_events(
    start_date: Optional[str] = Query(None, description="开始日期 YYYY-MM-DD"),
    end_date: Optional[str] = Query(None, description="结束日期 YYYY-MM-DD"),
    region: Optional[str] = Query(None, description="地区筛选"),
    event_type: Optional[str] = Query(None, description="事件类型: major/normal"),
    organization_id: Optional[int] = Query(None, description="组织ID"),
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(100, ge=1, le=1000, description="每页数量")
):
    """获取事件列表"""
    from main import engine
    
    try:
        with engine.connect() as conn:
            where_clauses = []
            params = {}
            
            if start_date:
                where_clauses.append("e.event_date >= :start_date")
                params["start_date"] = start_date
            
            if end_date:
                where_clauses.append("e.event_date <= :end_date")
                params["end_date"] = end_date
            
            if region:
                where_clauses.append("e.region = :region")
                params["region"] = region
            
            if event_type:
                where_clauses.append("e.event_type = :event_type")
                params["event_type"] = event_type
            
            if organization_id:
                where_clauses.append("e.organization_id = :org_id")
                params["org_id"] = organization_id
            
            where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
            
            # 查询总数
            count_result = conn.execute(
                text(f"""
                    SELECT COUNT(*) as total
                    FROM apt_events e
                    WHERE {where_sql}
                """),
                params
            ).scalar()
            
            # 查询分页数据
            offset = (page - 1) * page_size
            params["limit"] = page_size
            params["offset"] = offset
            
            results = conn.execute(
                text(f"""
                    SELECT e.id, e.event_date AS eventDate, e.title, e.description, 
                           e.event_type AS eventType, e.region, e.latitude, e.longitude,
                           e.severity, o.name AS organizationName, e.organization_id AS organizationId
                    FROM apt_events e
                    LEFT JOIN apt_organizations o ON e.organization_id = o.id
                    WHERE {where_sql}
                    ORDER BY e.event_date DESC, e.id DESC
                    LIMIT :limit OFFSET :offset
                """),
                params
            ).mappings().all()
            
            # 转换日期和Decimal对象
            events = []
            for r in results:
                event = {k: convert_to_json_serializable(v) for k, v in dict(r).items()}
                events.append(event)
            
            return JSONResponse(content={
                "code": 200,
                "msg": "查询成功",
                "data": {
                    "list": events,
                    "total": count_result or 0,
                    "page": page,
                    "pageSize": page_size
                }
            })
            
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"查询失败: {str(e)}", "data": None}
        )


@router.get("/heatmap")
def get_heatmap(
    start_date: Optional[str] = Query(None, description="开始日期 YYYY-MM-DD"),
    end_date: Optional[str] = Query(None, description="结束日期 YYYY-MM-DD")
):
    """获取时空热力图数据（地区-日期聚合）"""
    from main import engine
    
    try:
        with engine.connect() as conn:
            where_clauses = []
            params = {}
            
            if start_date:
                where_clauses.append("stat_date >= :start_date")
                params["start_date"] = start_date
            
            if end_date:
                where_clauses.append("stat_date <= :end_date")
                params["end_date"] = end_date
            
            where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
            
            # 优先从预聚合表查询
            results = conn.execute(
                text(f"""
                    SELECT stat_date AS date, region, event_count AS count
                    FROM region_event_stats
                    WHERE {where_sql}
                    ORDER BY stat_date ASC, region ASC
                """),
                params
            ).mappings().all()
            
            # 如果预聚合表无数据，则实时聚合
            if not results:
                event_where = where_sql.replace("stat_date", "event_date")
                results = conn.execute(
                    text(f"""
                        SELECT event_date AS date, region, COUNT(*) AS count
                        FROM apt_events
                        WHERE region IS NOT NULL AND {event_where}
                        GROUP BY event_date, region
                        ORDER BY event_date ASC, region ASC
                    """),
                    params
                ).mappings().all()
            
            # 转换数据类型
            heatmap_data = [{k: convert_to_json_serializable(v) for k, v in dict(r).items()} for r in results]
            
            return JSONResponse(content={
                "code": 200,
                "msg": "查询成功",
                "data": heatmap_data
            })
            
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"查询失败: {str(e)}", "data": None}
        )


@router.get("/timeline")
def get_timeline(
    organization_id: Optional[int] = Query(None, description="组织ID")
):
    """获取事件时间线"""
    from main import engine
    
    try:
        with engine.connect() as conn:
            where_clause = "WHERE e.organization_id = :org_id" if organization_id else "WHERE 1=1"
            params = {"org_id": organization_id} if organization_id else {}
            
            results = conn.execute(
                text(f"""
                    SELECT e.id, e.event_date AS date, e.title, e.description,
                           e.event_type AS type, o.name AS organization,
                           e.region, e.severity
                    FROM apt_events e
                    LEFT JOIN apt_organizations o ON e.organization_id = o.id
                    {where_clause}
                    ORDER BY e.event_date ASC
                """),
                params
            ).mappings().all()
            
            # 转换数据类型
            timeline = [{k: convert_to_json_serializable(v) for k, v in dict(r).items()} for r in results]
            
            return JSONResponse(content={
                "code": 200,
                "msg": "查询成功",
                "data": timeline
            })
            
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"查询失败: {str(e)}", "data": None}
        )


@router.get("/map-data")
def get_map_data():
    """获取地图标注数据（带经纬度的事件）"""
    from main import engine
    
    try:
        with engine.connect() as conn:
            # 获取最近30天的事件
            thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            
            results = conn.execute(
                text("""
                    SELECT e.id, e.event_date AS date, e.title, e.region,
                           e.latitude, e.longitude, e.event_type AS type,
                           e.severity, o.name AS organization
                    FROM apt_events e
                    LEFT JOIN apt_organizations o ON e.organization_id = o.id
                    WHERE e.latitude IS NOT NULL 
                      AND e.longitude IS NOT NULL
                      AND e.event_date >= :start_date
                    ORDER BY e.event_date DESC
                """),
                {"start_date": thirty_days_ago}
            ).mappings().all()
            
            # 转换数据类型
            map_data = [{k: convert_to_json_serializable(v) for k, v in dict(r).items()} for r in results]
            
            return JSONResponse(content={
                "code": 200,
                "msg": "查询成功",
                "data": map_data
            })
            
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": f"查询失败: {str(e)}", "data": None}
        )
