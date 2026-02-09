"""
Settings Router - Notification and Integration Configuration
"""
from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel

from .dependencies import get_current_user, get_db, check_permission, logger

# Import notification services
from notifications import (
    config as notification_config,
    send_slack_notification, send_email_notification
)

router = APIRouter(prefix="/settings", tags=["Settings"])

class NotificationSettings(BaseModel):
    slack_webhook_url: Optional[str] = None
    slack_enabled: bool = False
    email_enabled: bool = False
    sendgrid_api_key: Optional[str] = None
    email_from: Optional[str] = None
    email_to: Optional[str] = None
    elasticsearch_url: Optional[str] = None
    elasticsearch_api_key: Optional[str] = None
    elasticsearch_enabled: bool = False

@router.get("/notifications")
async def get_notification_settings(current_user: dict = Depends(get_current_user)):
    """Get current notification settings"""
    db = get_db()
    settings = await db.notification_settings.find_one({}, {"_id": 0})
    if not settings:
        settings = {
            "slack_webhook_url": "",
            "slack_enabled": False,
            "email_enabled": False,
            "sendgrid_api_key": "",
            "email_from": "",
            "email_to": "",
            "elasticsearch_url": "",
            "elasticsearch_api_key": "",
            "elasticsearch_enabled": False
        }
    
    # Mask sensitive data
    if settings.get("sendgrid_api_key"):
        settings["sendgrid_api_key"] = "***" + settings["sendgrid_api_key"][-4:]
    if settings.get("elasticsearch_api_key"):
        settings["elasticsearch_api_key"] = "***" + settings["elasticsearch_api_key"][-4:]
    
    return settings

@router.post("/notifications")
async def update_notification_settings(settings: NotificationSettings, current_user: dict = Depends(check_permission("write"))):
    """Update notification settings"""
    db = get_db()
    
    # Get current settings to preserve masked values
    current = await db.notification_settings.find_one({}, {"_id": 0}) or {}
    
    update_doc = {
        "slack_webhook_url": settings.slack_webhook_url if settings.slack_webhook_url else current.get("slack_webhook_url", ""),
        "slack_enabled": settings.slack_enabled,
        "email_enabled": settings.email_enabled,
        "email_from": settings.email_from if settings.email_from else current.get("email_from", ""),
        "email_to": settings.email_to if settings.email_to else current.get("email_to", ""),
        "elasticsearch_url": settings.elasticsearch_url if settings.elasticsearch_url else current.get("elasticsearch_url", ""),
        "elasticsearch_enabled": settings.elasticsearch_enabled,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "updated_by": current_user["id"]
    }
    
    # Only update API keys if new values provided (not masked)
    if settings.sendgrid_api_key and not settings.sendgrid_api_key.startswith("***"):
        update_doc["sendgrid_api_key"] = settings.sendgrid_api_key
    else:
        update_doc["sendgrid_api_key"] = current.get("sendgrid_api_key", "")
    
    if settings.elasticsearch_api_key and not settings.elasticsearch_api_key.startswith("***"):
        update_doc["elasticsearch_api_key"] = settings.elasticsearch_api_key
    else:
        update_doc["elasticsearch_api_key"] = current.get("elasticsearch_api_key", "")
    
    await db.notification_settings.update_one(
        {},
        {"$set": update_doc},
        upsert=True
    )
    
    # Update in-memory config
    notification_config.slack_webhook_url = update_doc.get("slack_webhook_url")
    notification_config.sendgrid_api_key = update_doc.get("sendgrid_api_key")
    notification_config.elasticsearch_url = update_doc.get("elasticsearch_url")
    notification_config.elasticsearch_api_key = update_doc.get("elasticsearch_api_key")
    
    return {"message": "Settings updated", "updated_at": update_doc["updated_at"]}

@router.post("/notifications/test")
async def test_notifications(channel: str, current_user: dict = Depends(get_current_user)):
    """Test notification channel"""
    db = get_db()
    settings = await db.notification_settings.find_one({}, {"_id": 0}) or {}
    
    if channel == "slack":
        webhook_url = settings.get("slack_webhook_url")
        if not webhook_url:
            raise HTTPException(status_code=400, detail="Slack webhook URL not configured")
        
        try:
            result = await send_slack_notification(
                "Test Notification",
                "This is a test message from Anti-AI Defense System",
                "info",
                webhook_url
            )
            return {"success": True, "message": "Slack test sent"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Slack test failed: {str(e)}")
    
    elif channel == "email":
        api_key = settings.get("sendgrid_api_key")
        from_email = settings.get("email_from")
        to_email = settings.get("email_to")
        
        if not all([api_key, from_email, to_email]):
            raise HTTPException(status_code=400, detail="Email settings incomplete")
        
        try:
            result = await send_email_notification(
                to_email,
                "Test: Anti-AI Defense System",
                "<h1>Test Notification</h1><p>This is a test email from Anti-AI Defense System.</p>",
                api_key,
                from_email
            )
            return {"success": True, "message": "Email test sent"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Email test failed: {str(e)}")
    
    raise HTTPException(status_code=400, detail=f"Unknown channel: {channel}")

# Elasticsearch Settings
@router.get("/elasticsearch/status")
async def get_elasticsearch_status(current_user: dict = Depends(get_current_user)):
    """Get Elasticsearch connection status"""
    db = get_db()
    settings = await db.notification_settings.find_one({}, {"_id": 0}) or {}
    
    es_url = settings.get("elasticsearch_url")
    es_enabled = settings.get("elasticsearch_enabled", False)
    
    if not es_url or not es_enabled:
        return {"connected": False, "message": "Elasticsearch not configured"}
    
    try:
        from elasticsearch import AsyncElasticsearch
        es_client = AsyncElasticsearch(
            [es_url],
            api_key=settings.get("elasticsearch_api_key")
        )
        info = await es_client.info()
        await es_client.close()
        return {
            "connected": True,
            "cluster_name": info.get("cluster_name"),
            "version": info.get("version", {}).get("number")
        }
    except Exception as e:
        logger.error(f"Elasticsearch connection error: {str(e)}")
        return {"connected": False, "error": str(e)}

@router.get("/elasticsearch/indices")
async def get_elasticsearch_indices(current_user: dict = Depends(get_current_user)):
    """Get Elasticsearch indices"""
    db = get_db()
    settings = await db.notification_settings.find_one({}, {"_id": 0}) or {}
    
    es_url = settings.get("elasticsearch_url")
    if not es_url:
        raise HTTPException(status_code=400, detail="Elasticsearch not configured")
    
    try:
        from elasticsearch import AsyncElasticsearch
        es_client = AsyncElasticsearch(
            [es_url],
            api_key=settings.get("elasticsearch_api_key")
        )
        indices = await es_client.cat.indices(format="json")
        await es_client.close()
        return {"indices": indices}
    except Exception as e:
        logger.error(f"Elasticsearch indices error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/elasticsearch/search")
async def search_elasticsearch(index: str, query: dict, current_user: dict = Depends(get_current_user)):
    """Search Elasticsearch"""
    db = get_db()
    settings = await db.notification_settings.find_one({}, {"_id": 0}) or {}
    
    es_url = settings.get("elasticsearch_url")
    if not es_url:
        raise HTTPException(status_code=400, detail="Elasticsearch not configured")
    
    try:
        from elasticsearch import AsyncElasticsearch
        es_client = AsyncElasticsearch(
            [es_url],
            api_key=settings.get("elasticsearch_api_key")
        )
        results = await es_client.search(index=index, body=query)
        await es_client.close()
        return results
    except Exception as e:
        logger.error(f"Elasticsearch search error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
