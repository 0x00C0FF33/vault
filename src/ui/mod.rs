//! UI Module
//!
//! Terminal user interface using ratatui.

// ratatui's geometry API is u16 throughout, so widths, offsets and scroll
// positions are constantly narrowed from usize. A terminal wide enough to
// truncate is not a case worth guarding.
#![allow(clippy::cast_possible_truncation)]

pub mod components;
pub mod renderer;

// Re-exports
pub use components::{
    MessageType,
    PasswordDialog,
};
