// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

pub fn main() {
    // Force a rebuild of this package, and thus anything dependent upon it, if AZURE_TEST_MODE changes.
    println!("cargo::rerun-if-env-changed=AZURE_TEST_MODE");
}
