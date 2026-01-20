//! Temporary admin handlers for database cleanup
//!
//! SECURITY WARNING: These endpoints have no authentication!
//! Remove this file after database cleanup is complete.

use actix_web::{web, HttpResponse};
use sqlx::PgPool;

use crate::error::AppResult;

/// DELETE /api/admin/cleanup-vps
///
/// Deletes ALL VPS records from the database (not terminated status only)
/// WARNING: No authentication! Use only for development/testing
pub async fn cleanup_all_vps(pool: web::Data<PgPool>) -> AppResult<HttpResponse> {
    let result = sqlx::query("DELETE FROM user_vps WHERE status NOT IN ('terminated')")
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "VPS records deleted",
        "rows_affected": result.rows_affected()
    })))
}

/// DELETE /api/admin/cleanup-vps/:email
///
/// Deletes VPS records for a specific user by email
/// WARNING: No authentication! Use only for development/testing
pub async fn cleanup_user_vps(
    pool: web::Data<PgPool>,
    email: web::Path<String>,
) -> AppResult<HttpResponse> {
    let result = sqlx::query(
        "DELETE FROM user_vps WHERE user_id IN (SELECT id FROM users WHERE email = $1)"
    )
    .bind(email.as_str())
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": format!("VPS records deleted for {}", email),
        "rows_affected": result.rows_affected()
    })))
}

/// GET /api/admin/list-vps
///
/// Lists all VPS records
/// WARNING: No authentication! Use only for development/testing
pub async fn list_all_vps(pool: web::Data<PgPool>) -> AppResult<HttpResponse> {
    #[derive(serde::Serialize, sqlx::FromRow)]
    struct VpsRecord {
        id: uuid::Uuid,
        user_id: uuid::Uuid,
        device_type: String,
        hostname: String,
        ip_address: Option<String>,
        status: String,
    }

    let records: Vec<VpsRecord> = sqlx::query_as(
        "SELECT id, user_id, device_type, hostname, ip_address, status FROM user_vps ORDER BY created_at DESC"
    )
    .fetch_all(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "vps_records": records,
        "total": records.len()
    })))
}
