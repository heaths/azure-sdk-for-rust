#![allow(clippy::module_inception)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::derive_partial_eq_without_eq)]
#![allow(clippy::new_without_default)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::invalid_html_tags)]
#![allow(rustdoc::broken_intra_doc_links)]
#[cfg(feature = "package-2016-07")]
pub mod package_2016_07;
#[cfg(feature = "package-2017-04")]
pub mod package_2017_04;
#[cfg(feature = "package-2018-01-preview")]
pub mod package_2018_01_preview;
#[cfg(feature = "package-2021-11-01")]
pub mod package_2021_11_01;
#[cfg(feature = "package-2024-01-01")]
pub mod package_2024_01_01;
#[cfg(all(feature = "default_tag", feature = "package-2024-01-01"))]
pub use package_2024_01_01::*;
