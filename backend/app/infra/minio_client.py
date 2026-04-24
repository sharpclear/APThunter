import io
import uuid

from fastapi import UploadFile
from minio import Minio

from app.core.config import (
    MINIO_ACCESS_KEY,
    MINIO_BUCKET,
    MINIO_ENDPOINT,
    MINIO_SECRET_KEY,
)

minio_client = Minio(
    MINIO_ENDPOINT,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=False,
)
if not minio_client.bucket_exists(MINIO_BUCKET):
    minio_client.make_bucket(MINIO_BUCKET)


def upload_to_minio(file: UploadFile, bucket: str = MINIO_BUCKET):
    ext = file.filename.split(".")[-1] if file.filename else ""
    key = f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex
    data = file.file.read()
    file_stream = io.BytesIO(data)
    minio_client.put_object(
        bucket,
        key,
        file_stream,
        length=len(data),
        content_type=file.content_type or "application/octet-stream",
    )
    file.file.seek(0)
    return key, len(data)
