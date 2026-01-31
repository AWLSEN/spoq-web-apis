//! In-memory async operation tracking for long-running VPS provisioning.
//!
//! This module provides a simple, thread-safe way to track async operations
//! without database overhead. Operations auto-expire after completion.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// How long to keep completed operations before cleanup (5 minutes)
const OPERATION_TTL: Duration = Duration::from_secs(300);

/// How often to run cleanup (1 minute)
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Operation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    /// Queued, waiting to start
    Pending,
    /// Currently executing
    Running,
    /// Completed successfully
    Completed,
    /// Failed with error
    Failed,
}

/// Progress step for detailed status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressStep {
    pub name: String,
    pub completed: bool,
}

/// Operation state stored in memory
#[derive(Debug, Clone)]
pub struct Operation {
    pub id: Uuid,
    pub user_id: Uuid,
    pub operation_type: String,
    pub status: OperationStatus,
    pub progress: u8,
    pub steps: Vec<ProgressStep>,
    pub message: String,
    pub result: Option<OperationResult>,
    pub error: Option<String>,
    pub created_at: Instant,
    pub completed_at: Option<Instant>,
}

/// Result data for successful operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    pub hostname: String,
    pub ip_address: String,
    pub jwt_secret: String,
    pub ssh_password: String,
    pub vps_id: Option<Uuid>,
}

/// Public response for operation status
#[derive(Debug, Serialize)]
pub struct OperationResponse {
    pub id: Uuid,
    pub operation_type: String,
    pub status: OperationStatus,
    pub progress: u8,
    pub steps: Vec<ProgressStep>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<OperationResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl From<&Operation> for OperationResponse {
    fn from(op: &Operation) -> Self {
        Self {
            id: op.id,
            operation_type: op.operation_type.clone(),
            status: op.status.clone(),
            progress: op.progress,
            steps: op.steps.clone(),
            message: op.message.clone(),
            result: op.result.clone(),
            error: op.error.clone(),
        }
    }
}

/// Thread-safe operation store
#[derive(Clone)]
pub struct OperationStore {
    operations: Arc<DashMap<Uuid, Operation>>,
}

impl Default for OperationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationStore {
    pub fn new() -> Self {
        let store = Self {
            operations: Arc::new(DashMap::new()),
        };

        // Start background cleanup task
        let ops = store.operations.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(CLEANUP_INTERVAL).await;
                Self::cleanup(&ops);
            }
        });

        store
    }

    /// Create a new operation and return its ID
    pub fn create(
        &self,
        user_id: Uuid,
        operation_type: &str,
        steps: Vec<&str>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let operation = Operation {
            id,
            user_id,
            operation_type: operation_type.to_string(),
            status: OperationStatus::Pending,
            progress: 0,
            steps: steps
                .into_iter()
                .map(|name| ProgressStep {
                    name: name.to_string(),
                    completed: false,
                })
                .collect(),
            message: "Queued".to_string(),
            result: None,
            error: None,
            created_at: Instant::now(),
            completed_at: None,
        };
        self.operations.insert(id, operation);
        tracing::info!("Operation created: {} ({})", id, operation_type);
        id
    }

    /// Get operation by ID (only if user matches)
    pub fn get(&self, id: Uuid, user_id: Uuid) -> Option<OperationResponse> {
        self.operations
            .get(&id)
            .filter(|op| op.user_id == user_id)
            .map(|op| OperationResponse::from(op.value()))
    }

    /// Get operation for internal use (no user check)
    pub fn get_internal(&self, id: Uuid) -> Option<Operation> {
        self.operations.get(&id).map(|op| op.value().clone())
    }

    /// Update operation status
    pub fn set_status(&self, id: Uuid, status: OperationStatus, message: &str) {
        if let Some(mut op) = self.operations.get_mut(&id) {
            op.status = status.clone();
            op.message = message.to_string();
            if matches!(status, OperationStatus::Completed | OperationStatus::Failed) {
                op.completed_at = Some(Instant::now());
            }
            tracing::info!("Operation {} status: {:?} - {}", id, status, message);
        }
    }

    /// Update operation progress (0-100)
    pub fn set_progress(&self, id: Uuid, progress: u8, message: &str) {
        if let Some(mut op) = self.operations.get_mut(&id) {
            op.progress = progress.min(100);
            op.message = message.to_string();
        }
    }

    /// Mark a step as completed
    pub fn complete_step(&self, id: Uuid, step_index: usize) {
        if let Some(mut op) = self.operations.get_mut(&id) {
            if step_index < op.steps.len() {
                op.steps[step_index].completed = true;
                // Calculate progress based on completed steps
                let completed = op.steps.iter().filter(|s| s.completed).count();
                op.progress = ((completed * 100) / op.steps.len()) as u8;
            }
        }
    }

    /// Set operation result (on success)
    pub fn set_result(&self, id: Uuid, result: OperationResult) {
        if let Some(mut op) = self.operations.get_mut(&id) {
            op.result = Some(result);
            op.status = OperationStatus::Completed;
            op.progress = 100;
            op.message = "Completed successfully".to_string();
            op.completed_at = Some(Instant::now());
        }
    }

    /// Set operation error (on failure)
    pub fn set_error(&self, id: Uuid, error: &str) {
        if let Some(mut op) = self.operations.get_mut(&id) {
            op.error = Some(error.to_string());
            op.status = OperationStatus::Failed;
            op.message = "Failed".to_string();
            op.completed_at = Some(Instant::now());
        }
    }

    /// Cleanup expired operations
    fn cleanup(ops: &DashMap<Uuid, Operation>) {
        let now = Instant::now();
        ops.retain(|_, op| {
            // Keep if not completed or completed less than TTL ago
            match op.completed_at {
                None => true,
                Some(completed) => now.duration_since(completed) < OPERATION_TTL,
            }
        });
    }
}
