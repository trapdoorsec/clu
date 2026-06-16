# Database Layer Implementation

This document describes the database layer added to CLU for persisting analysis reports and tracking package processing status.

## Overview

The database layer uses **SQLite** with **sqlx** for async database operations. It provides:
- Persistent storage of analysis reports
- Real-time package processing status tracking
- Query and filtering capabilities for building a web UI
- Automatic migrations and connection pooling

## Database Schema

### Table: `analysis_reports`

Stores complete analysis reports with all findings from all pipeline stages.

```sql
CREATE TABLE analysis_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    package_version TEXT,
    timestamp TEXT NOT NULL,
    overall_risk_score INTEGER NOT NULL,
    is_malicious INTEGER NOT NULL,
    recommendation TEXT NOT NULL,  -- "BLOCK", "REVIEW", "SAFE"
    report_json TEXT NOT NULL,     -- Full AnalysisReport as JSON
    created_at TEXT NOT NULL,
    UNIQUE(package_name, timestamp)
);
```

**Indexes:**
- `idx_risk_score` - Fast filtering by risk level
- `idx_recommendation` - Filter by BLOCK/REVIEW/SAFE
- `idx_package_name` - Package name lookups
- `idx_timestamp` - Sort by newest first

### Table: `package_status`

Tracks real-time processing status for the live feed feature.

```sql
CREATE TABLE package_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,          -- queued, heuristics, typosquat, yara, llm, completed, failed
    current_stage TEXT,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    error_message TEXT
);
```

**Indexes:**
- `idx_status` - Query packages by processing status

## Configuration

Add to `config.toml`:

```toml
[database]
# Database file location
url = "sqlite://config/data/clu.db"

# Enable/disable database persistence
enable = true
```

**Defaults:**
- `url`: `sqlite://config/data/clu.db`
- `enable`: `true`

Set `enable = false` to disable database persistence (useful for testing).

## API Reference

### Database Module: `src/db/mod.rs`

#### Creating a Database Connection

```rust
use clu::db::Database;

let db = Database::new("sqlite://config/data/clu.db").await?;
```

#### Inserting Reports

```rust
let report = AnalysisReport {
    package_name: "suspicious-package".to_string(),
    overall_risk_score: 85,
    is_malicious: true,
    recommendation: "BLOCK".to_string(),
    // ... other fields
};

let id = db.insert_report(&report).await?;
```

#### Querying Reports

```rust
use clu::db::QueryFilters;

// Get all BLOCK recommendations
let filters = QueryFilters {
    recommendation: Some("BLOCK".to_string()),
    ..Default::default()
};

let reports = db.query_reports(&filters).await?;

// Get high-risk packages (score >= 70)
let filters = QueryFilters {
    min_risk_score: Some(70),
    limit: Some(50),
    offset: Some(0),
    ..Default::default()
};

let high_risk = db.query_reports(&filters).await?;
```

#### Available Filters

```rust
pub struct QueryFilters {
    pub min_risk_score: Option<u8>,      // Minimum risk score (0-100)
    pub max_risk_score: Option<u8>,      // Maximum risk score
    pub recommendation: Option<String>,   // "BLOCK", "REVIEW", "SAFE"
    pub is_malicious: Option<bool>,      // Filter by malicious flag
    pub package_name: Option<String>,    // Package name (supports LIKE)
    pub limit: Option<i64>,              // Pagination limit
    pub offset: Option<i64>,             // Pagination offset
}
```

#### Package Status Tracking

```rust
use clu::db::PackageStatus;

// Update package status
db.update_package_status("my-package", PackageStatus::Heuristics, None).await?;

// Get current status
let (status, error) = db.get_package_status("my-package").await?;

// Get all packages currently being processed
let processing = db.get_processing_packages().await?;
```

#### Package Status States

```rust
pub enum PackageStatus {
    Queued,      // Package queued for analysis
    Heuristics,  // Running heuristic analysis
    Typosquat,   // Running typosquat detection
    Yara,       // Running YARA scan (formerly GuardDog)
    Llm,         // Running LLM analysis
    Completed,   // Analysis complete
    Failed,      // Analysis failed
}
```

#### Counting Reports

```rust
let count = db.count_reports(&filters).await?;
```

#### Cleanup Old Reports

```rust
// Delete reports older than 30 days
let deleted = db.delete_old_reports(30).await?;
```

## Integration with Watch Feed

The database is automatically integrated into the `watch_feed` pipeline:

1. **Initialization**: Database connection pool created at startup
2. **Status Updates**: Package status updated at each pipeline stage
3. **Report Persistence**: Complete reports saved on successful analysis
4. **Error Handling**: Failed analyses marked with error messages

### Status Flow

```
New Package → Queued → Heuristics → Typosquat → (YARA) → (LLM) → Completed
                                                                         ↓
                                                                    (or Failed)
```

## Example: Building a Web API

Here's how you might use this for a web service:

```rust
use axum::{Router, routing::get, Json};
use clu::db::{Database, QueryFilters};
use clu::output::AnalysisReport;

async fn get_dangerous_packages(
    db: Database
) -> Json<Vec<AnalysisReport>> {
    let filters = QueryFilters {
        recommendation: Some("BLOCK".to_string()),
        limit: Some(100),
        ..Default::default()
    };
    
    let reports = db.query_reports(&filters).await.unwrap();
    Json(reports)
}

async fn get_package_details(
    db: Database,
    package_name: String
) -> Json<Option<AnalysisReport>> {
    let report = db.get_report(&package_name).await.unwrap();
    Json(report)
}
```

## Data Types Exported

All analysis result types support both `Serialize` and `Deserialize` for database storage:

- `AnalysisReport` - Complete analysis report
- `HeuristicMatch` - Heuristic rule matches
- `TypoSquatterMatch` - Typosquat findings
- `YaraScanResult` - YARA scan results (replaces former `GuardDogResult`)
- `YaraRuleMatch` - Individual YARA rule matches (replaces former `GuardDogFinding`)
- `LlmAnalysisResult` - LLM semantic analysis
- `PromptInjectionDetection` - LLM injection detection

> **Migration note:** Existing databases storing `guarddog_result` fields are automatically migrated to `yara_result` on first boot. The `package_status` status value `guarddog` is also renamed to `yara`. Example log output:
> ```
> Running YARA migration: renaming guarddog_result → yara_result in stored reports
> ```

## Testing

Run database tests:

```bash
cargo test --lib db::tests
```

Tests include:
- ✅ Database creation and migrations
- ✅ Insert and retrieve reports
- ✅ Query filters (risk score, recommendation, etc.)
- ✅ Package status tracking
- ✅ Status transitions

## Performance Considerations

- **Connection Pooling**: 5 concurrent connections by default
- **Indexes**: All common query patterns are indexed
- **JSON Storage**: Full reports stored as JSON for flexibility
- **SQLite**: Single-file database, no separate server needed

## Future Enhancements

Potential improvements for the web service:

1. **Real-time Updates**: Use WebSocket or SSE to push status updates
2. **Aggregation Queries**: Stats like "packages per day", "avg risk score"
3. **Search**: Full-text search on package names and descriptions
4. **Export**: Bulk export to JSON/CSV for reporting
5. **Retention Policies**: Automatic cleanup of old reports

## File Locations

- **Module**: `src/db/mod.rs`
- **Config**: `src/config/mod.rs` (DatabaseConfig struct)
- **Default DB**: `config/data/clu.db`
- **Integration**: `src/main.rs` (watch_feed and analyze_package functions)
