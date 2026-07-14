//! BNS API types, indexer/server RPC client, and SN-side BNS write controller.
//!
//! RPC APIs expose projection reads and signed raw-transaction submission.
//! Write request structures remain reusable by the EVM calldata/signing
//! helpers, while authorization is enforced by the BNS contract through
//! `msg.sender`.

pub mod dns_document;

mod error;
mod evm;
pub mod model;
mod rpc;
mod sn_bns_controller;
mod sn_bns_store;

pub use error::{BnsRegistryError, BnsRegistryResult};
pub use evm::*;
pub use model::*;
pub use rpc::*;
pub use sn_bns_controller::*;
pub use sn_bns_store::*;
