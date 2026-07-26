"""基于历史图谱的域名 APT 归因能力。

该包只包含可导入的算法和实时基础设施补全代码，不依赖 FastAPI、
数据库、MinIO 或 Celery，也不会修改历史图谱。
"""

from .engine import (
    AttributionConfigurationError,
    DomainAttributionEngine,
    attribute_domains,
)
from .infrastructure import (
    InfrastructureRecord,
    LiveInfrastructureConfig,
    LiveInfrastructureLookup,
)

__all__ = [
    "AttributionConfigurationError",
    "DomainAttributionEngine",
    "InfrastructureRecord",
    "LiveInfrastructureConfig",
    "LiveInfrastructureLookup",
    "attribute_domains",
]
