#!/usr/bin/env python3
"""
数据清理脚本
定期清理数据库、文件系统和MinIO中的孤立数据

清理规则：
1. 文件系统中的pkl：删除 user_models 表中没有任何记录的模型（仅 model_type='custom'），
   且 tasks 表中无记录的模型，同时删除其标准化器文件和关联的训练数据
2. MinIO中：
   - uploads桶：删除 files 表中没有记录的文件
   - results桶：删除 tasks 表中 extra 字段的 result_file_key 都没有的文件
   - traindata桶：删除与已删除模型关联的训练数据文件
3. 数据库中：删除 models 表中有但 user_models 表中无任何映射关系的模型（仅 model_type='custom'，且 tasks 表中无记录）

执行频率：每30天执行一次
"""

import os
import sys
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Set, Dict, Optional
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import create_engine, text
from minio import Minio
from minio.error import S3Error

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cleanup.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 从环境变量获取配置
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "123456789")
MYSQL_URL = os.getenv("MYSQL_URL", "mysql+pymysql://apthunter:4CyUhr2zu6!@localhost:3306/apthunter_new")

# MinIO桶名称
UPLOADS_BUCKET = "uploads"
RESULTS_BUCKET = "results"
TRAINDATA_BUCKET = "traindata"

# 模型保存目录（相对于脚本位置）
SCRIPT_DIR = Path(__file__).parent
MODELS_BASE_DIR = SCRIPT_DIR.parent / "app" / "models"
SAVED_MODEL_DIR = MODELS_BASE_DIR / "saved_model"


def get_scaler_path_from_model_path(model_path: str) -> str:
    """
    根据模型路径生成标准化器路径
    
    规则：将文件名中的 'model' 替换为 'scaler'
    例如：saved_model/model_123.pkl -> saved_model/scaler_123.pkl
    
    参数:
        model_path: 模型文件的相对路径（相对于 models 目录）或绝对路径
    
    返回:
        scaler_path: 标准化器文件的路径（绝对路径）
    """
    # 如果已经是绝对路径，直接使用
    if os.path.isabs(model_path):
        model_path_abs = model_path
    else:
        # 相对路径：先尝试相对于MODELS_BASE_DIR
        model_path_abs = str(MODELS_BASE_DIR / model_path)
        # 如果文件不存在，尝试直接使用model_path（可能是相对于当前工作目录）
        if not os.path.exists(model_path_abs) and os.path.exists(model_path):
            model_path_abs = os.path.abspath(model_path)
    
    # 获取目录和文件名
    dir_name = os.path.dirname(model_path_abs)
    file_name = os.path.basename(model_path_abs)
    
    # 将文件名中的 'model' 替换为 'scaler'（只替换第一个）
    scaler_file_name = file_name.replace('model', 'scaler', 1)
    scaler_path = os.path.join(dir_name, scaler_file_name)
    
    return scaler_path


def cleanup_filesystem_pkl(engine, minio_client: Minio) -> Dict[str, int]:
    """
    清理文件系统中的pkl文件
    
    删除条件：
    - model_type='custom'
    - user_models 表中无记录
    - tasks 表中无记录
    
    同时删除：
    - 模型pkl文件
    - 标准化器pkl文件
    - training_tasks 表中的训练记录
    - MinIO traindata 桶中的训练数据
    """
    stats = {
        "models_deleted": 0,
        "pkl_files_deleted": 0,
        "training_tasks_deleted": 0,
        "training_data_deleted": 0,
        "errors": 0
    }
    
    try:
        with engine.connect() as conn:
            # 查询需要删除的模型（custom类型，user_models中无记录，tasks中无记录）
            query = text("""
                SELECT m.id, m.model_path, m.name
                FROM models m
                WHERE m.model_type = 'custom'
                  AND m.id NOT IN (SELECT DISTINCT model_id FROM user_models WHERE model_id IS NOT NULL)
                  AND m.id NOT IN (SELECT DISTINCT model_id FROM tasks WHERE model_id IS NOT NULL)
            """)
            rows = conn.execute(query).mappings().all()
            
            logger.info(f"找到 {len(rows)} 个需要删除的模型")
            
            for row in rows:
                model_id = row["id"]
                model_path = row["model_path"]
                model_name = row["name"]
                
                if not model_path:
                    logger.warning(f"模型 {model_id} ({model_name}) 的 model_path 为空，跳过")
                    continue
                
                try:
                    # 1. 删除文件系统中的pkl文件
                    # 处理相对路径和绝对路径
                    if os.path.isabs(model_path):
                        model_path_abs = model_path
                    else:
                        # 相对路径可能是相对于models目录的
                        model_path_abs = str(MODELS_BASE_DIR / model_path)
                        # 如果文件不存在，尝试直接使用model_path（可能是相对于当前工作目录）
                        if not os.path.exists(model_path_abs):
                            model_path_abs = model_path
                    
                    scaler_path_abs = get_scaler_path_from_model_path(model_path_abs)
                    
                    deleted_files = []
                    
                    # 删除模型文件
                    if os.path.exists(model_path_abs):
                        os.remove(model_path_abs)
                        deleted_files.append(model_path_abs)
                        logger.info(f"已删除模型文件: {model_path_abs}")
                    
                    # 删除标准化器文件
                    if os.path.exists(scaler_path_abs):
                        os.remove(scaler_path_abs)
                        deleted_files.append(scaler_path_abs)
                        logger.info(f"已删除标准化器文件: {scaler_path_abs}")
                    
                    if deleted_files:
                        stats["pkl_files_deleted"] += len(deleted_files)
                    
                    # 2. 删除 training_tasks 表中的训练记录
                    training_tasks_query = text("""
                        SELECT task_id, training_data_file_id
                        FROM training_tasks
                        WHERE model_id = :model_id
                    """)
                    training_tasks = conn.execute(training_tasks_query, {"model_id": model_id}).mappings().all()
                    
                    training_data_file_ids = []
                    for task in training_tasks:
                        if task["training_data_file_id"]:
                            training_data_file_ids.append(task["training_data_file_id"])
                    
                    if training_tasks:
                        delete_training_tasks_query = text("""
                            DELETE FROM training_tasks WHERE model_id = :model_id
                        """)
                        conn.execute(delete_training_tasks_query, {"model_id": model_id})
                        conn.commit()
                        stats["training_tasks_deleted"] += len(training_tasks)
                        logger.info(f"已删除 {len(training_tasks)} 条训练任务记录")
                    
                    # 3. 删除 MinIO traindata 桶中的训练数据
                    if training_data_file_ids:
                        # 构建IN子句的占位符
                        placeholders = ','.join([':file_id_' + str(i) for i in range(len(training_data_file_ids))])
                        params = {f'file_id_{i}': file_id for i, file_id in enumerate(training_data_file_ids)}
                        params['bucket'] = TRAINDATA_BUCKET
                        
                        files_query = text(f"""
                            SELECT object_key, bucket
                            FROM files
                            WHERE id IN ({placeholders}) AND bucket = :bucket
                        """)
                        files = conn.execute(files_query, params).mappings().all()
                        
                        for file_row in files:
                            object_key = file_row["object_key"]
                            try:
                                minio_client.remove_object(TRAINDATA_BUCKET, object_key)
                                stats["training_data_deleted"] += 1
                                logger.info(f"已删除MinIO训练数据: {TRAINDATA_BUCKET}/{object_key}")
                            except S3Error as e:
                                logger.error(f"删除MinIO训练数据失败 {TRAINDATA_BUCKET}/{object_key}: {e}")
                                stats["errors"] += 1
                    
                    # 4. 删除 models 表中的记录
                    delete_model_query = text("DELETE FROM models WHERE id = :model_id")
                    conn.execute(delete_model_query, {"model_id": model_id})
                    conn.commit()
                    stats["models_deleted"] += 1
                    logger.info(f"已删除模型记录: {model_id} ({model_name})")
                    
                except Exception as e:
                    logger.error(f"删除模型 {model_id} ({model_name}) 时出错: {e}", exc_info=True)
                    stats["errors"] += 1
                    
    except Exception as e:
        logger.error(f"清理文件系统pkl文件时出错: {e}", exc_info=True)
        stats["errors"] += 1
    
    return stats


def cleanup_minio_uploads(engine, minio_client: Minio) -> Dict[str, int]:
    """
    清理MinIO uploads桶中的孤立文件
    
    删除条件：uploads桶中有但 files 表中没有记录的文件
    """
    stats = {
        "files_deleted": 0,
        "errors": 0
    }
    
    try:
        # 1. 获取 files 表中所有 uploads 桶的文件
        with engine.connect() as conn:
            query = text("""
                SELECT object_key FROM files WHERE bucket = :bucket
            """)
            rows = conn.execute(query, {"bucket": UPLOADS_BUCKET}).mappings().all()
            db_object_keys = {row["object_key"] for row in rows}
        
        logger.info(f"数据库中有 {len(db_object_keys)} 个 uploads 桶的文件记录")
        
        # 2. 检查MinIO桶是否存在
        if not minio_client.bucket_exists(UPLOADS_BUCKET):
            logger.warning(f"MinIO桶 {UPLOADS_BUCKET} 不存在，跳过清理")
            return stats
        
        # 3. 列出MinIO中的所有对象
        minio_objects = []
        try:
            objects = minio_client.list_objects(UPLOADS_BUCKET, recursive=True)
            for obj in objects:
                minio_objects.append(obj.object_name)
        except S3Error as e:
            logger.error(f"列出MinIO对象失败: {e}")
            stats["errors"] += 1
            return stats
        
        logger.info(f"MinIO {UPLOADS_BUCKET} 桶中有 {len(minio_objects)} 个文件")
        
        # 4. 删除不在数据库中的文件
        for object_key in minio_objects:
            if object_key not in db_object_keys:
                try:
                    minio_client.remove_object(UPLOADS_BUCKET, object_key)
                    stats["files_deleted"] += 1
                    logger.info(f"已删除孤立文件: {UPLOADS_BUCKET}/{object_key}")
                except S3Error as e:
                    logger.error(f"删除文件失败 {UPLOADS_BUCKET}/{object_key}: {e}")
                    stats["errors"] += 1
                    
    except Exception as e:
        logger.error(f"清理MinIO uploads桶时出错: {e}", exc_info=True)
        stats["errors"] += 1
    
    return stats


def cleanup_minio_results(engine, minio_client: Minio) -> Dict[str, int]:
    """
    清理MinIO results桶中的孤立文件
    
    删除条件：results桶中有但 tasks 表中 extra 字段的 result_file_key 都没有的文件
    """
    stats = {
        "files_deleted": 0,
        "errors": 0
    }
    
    try:
        # 1. 获取 tasks 表中所有 result_file_key
        with engine.connect() as conn:
            query = text("""
                SELECT extra FROM tasks WHERE extra IS NOT NULL
            """)
            rows = conn.execute(query).mappings().all()
            
            result_file_keys = set()
            for row in rows:
                extra = row["extra"]
                if extra:
                    try:
                        # extra可能是JSON字符串或字典
                        if isinstance(extra, str):
                            extra_dict = json.loads(extra)
                        else:
                            extra_dict = extra
                        
                        result_file_key = extra_dict.get("result_file_key")
                        if result_file_key:
                            result_file_keys.add(result_file_key)
                    except (json.JSONDecodeError, TypeError) as e:
                        logger.warning(f"解析extra字段失败: {e}")
                        continue
        
        logger.info(f"数据库中有 {len(result_file_keys)} 个 result_file_key 记录")
        
        # 2. 检查MinIO桶是否存在
        if not minio_client.bucket_exists(RESULTS_BUCKET):
            logger.warning(f"MinIO桶 {RESULTS_BUCKET} 不存在，跳过清理")
            return stats
        
        # 3. 列出MinIO中的所有对象
        minio_objects = []
        try:
            objects = minio_client.list_objects(RESULTS_BUCKET, recursive=True)
            for obj in objects:
                minio_objects.append(obj.object_name)
        except S3Error as e:
            logger.error(f"列出MinIO对象失败: {e}")
            stats["errors"] += 1
            return stats
        
        logger.info(f"MinIO {RESULTS_BUCKET} 桶中有 {len(minio_objects)} 个文件")
        
        # 4. 删除不在数据库中的文件
        for object_key in minio_objects:
            if object_key not in result_file_keys:
                try:
                    minio_client.remove_object(RESULTS_BUCKET, object_key)
                    stats["files_deleted"] += 1
                    logger.info(f"已删除孤立文件: {RESULTS_BUCKET}/{object_key}")
                except S3Error as e:
                    logger.error(f"删除文件失败 {RESULTS_BUCKET}/{object_key}: {e}")
                    stats["errors"] += 1
                    
    except Exception as e:
        logger.error(f"清理MinIO results桶时出错: {e}", exc_info=True)
        stats["errors"] += 1
    
    return stats


def cleanup_database_models(engine) -> Dict[str, int]:
    """
    清理数据库中的孤立模型记录
    
    删除条件：
    - model_type='custom'
    - user_models 表中无记录
    - tasks 表中无记录
    """
    stats = {
        "models_deleted": 0,
        "errors": 0
    }
    
    try:
        with engine.connect() as conn:
            # 查询需要删除的模型（custom类型，user_models中无记录，tasks中无记录）
            query = text("""
                SELECT m.id, m.name
                FROM models m
                WHERE m.model_type = 'custom'
                  AND m.id NOT IN (SELECT DISTINCT model_id FROM user_models WHERE model_id IS NOT NULL)
                  AND m.id NOT IN (SELECT DISTINCT model_id FROM tasks WHERE model_id IS NOT NULL)
            """)
            rows = conn.execute(query).mappings().all()
            
            logger.info(f"找到 {len(rows)} 个需要删除的模型记录")
            
            for row in rows:
                model_id = row["id"]
                model_name = row["name"]
                
                try:
                    delete_query = text("DELETE FROM models WHERE id = :model_id")
                    conn.execute(delete_query, {"model_id": model_id})
                    conn.commit()
                    stats["models_deleted"] += 1
                    logger.info(f"已删除模型记录: {model_id} ({model_name})")
                except Exception as e:
                    logger.error(f"删除模型记录 {model_id} ({model_name}) 时出错: {e}")
                    stats["errors"] += 1
                    
    except Exception as e:
        logger.error(f"清理数据库模型记录时出错: {e}", exc_info=True)
        stats["errors"] += 1
    
    return stats


def run_cleanup():
    """
    执行清理任务
    """
    logger.info("=" * 80)
    logger.info("开始执行清理任务")
    logger.info(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("=" * 80)
    
    # 初始化数据库连接
    try:
        engine = create_engine(MYSQL_URL, echo=False, future=True)
        logger.info("数据库连接成功")
    except Exception as e:
        logger.error(f"数据库连接失败: {e}")
        return
    
    # 初始化MinIO客户端
    try:
        minio_client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=False
        )
        logger.info("MinIO客户端初始化成功")
    except Exception as e:
        logger.error(f"MinIO客户端初始化失败: {e}")
        return
    
    # 执行各项清理任务
    all_stats = {
        "filesystem_pkl": {},
        "minio_uploads": {},
        "minio_results": {},
        "database_models": {}
    }
    
    try:
        # 1. 清理文件系统中的pkl文件（同时会删除关联的训练数据和训练任务）
        logger.info("\n" + "-" * 80)
        logger.info("1. 清理文件系统中的pkl文件")
        logger.info("-" * 80)
        all_stats["filesystem_pkl"] = cleanup_filesystem_pkl(engine, minio_client)
        
        # 2. 清理MinIO uploads桶
        logger.info("\n" + "-" * 80)
        logger.info("2. 清理MinIO uploads桶")
        logger.info("-" * 80)
        all_stats["minio_uploads"] = cleanup_minio_uploads(engine, minio_client)
        
        # 3. 清理MinIO results桶
        logger.info("\n" + "-" * 80)
        logger.info("3. 清理MinIO results桶")
        logger.info("-" * 80)
        all_stats["minio_results"] = cleanup_minio_results(engine, minio_client)
        
        # 4. 清理数据库中的模型记录（作为补充，因为文件系统清理已经删除了大部分）
        logger.info("\n" + "-" * 80)
        logger.info("4. 清理数据库中的模型记录")
        logger.info("-" * 80)
        all_stats["database_models"] = cleanup_database_models(engine)
        
    except Exception as e:
        logger.error(f"执行清理任务时出错: {e}", exc_info=True)
    
    # 输出统计信息
    logger.info("\n" + "=" * 80)
    logger.info("清理任务完成")
    logger.info(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("=" * 80)
    logger.info("统计信息:")
    logger.info(json.dumps(all_stats, indent=2, ensure_ascii=False))
    logger.info("=" * 80 + "\n")


def main():
    """
    主函数：设置定时任务或立即执行
    """
    # 检查是否作为独立脚本运行（立即执行一次）
    if len(sys.argv) > 1 and sys.argv[1] == "--run-once":
        logger.info("立即执行清理任务（单次运行模式）")
        run_cleanup()
        return
    
    # 否则使用APScheduler定时执行
    logger.info("启动定时清理任务（每30天执行一次）")
    scheduler = BlockingScheduler()
    
    # 每30天执行一次
    scheduler.add_job(
        run_cleanup,
        trigger=IntervalTrigger(days=30),
        id='cleanup_job',
        name='数据清理任务',
        replace_existing=True
    )
    
    # 立即执行一次
    logger.info("立即执行一次清理任务...")
    run_cleanup()
    
    try:
        logger.info("定时任务已启动，等待下次执行（30天后）...")
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("定时任务已停止")
        scheduler.shutdown()


if __name__ == "__main__":
    main()
