#![allow(clippy::module_inception)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::derive_partial_eq_without_eq)]
#[cfg(feature = "package-2022-02-02")]
pub mod package_2022_02_02;
#[cfg(all(feature = "package-2022-02-02", not(feature = "no-default-tag")))]
pub use package_2022_02_02::*;