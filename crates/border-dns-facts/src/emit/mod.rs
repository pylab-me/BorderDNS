//! Fact emission types for the BorderDNS governance pipeline.
//!
//! Contains:
//! - `FactEmitter` — lightweight fact emission from the pipeline hot path
//! - `ObservationTask` — background observation task model
//! - `ObservationTaskKind` — types of observation tasks

pub mod observation;

pub use observation::*;
