# azure_storage_blobs

> Microsoft is developing the official Azure SDK for Rust crates and has no plans to update this unofficial crate.
> In the future we may release an official version that may have a different package name.
> If releasing an official version of this crate is important to you [let us know](https://github.com/Azure/azure-sdk-for-rust/issues/new/choose).
>
> Source for this crate can now be found in <https://github.com/Azure/azure-sdk-for-rust/tree/legacy>.
> To monitor for an official, supported version of this crate, see <https://aka.ms/azsdk/releases>.

This crate is from the [Azure SDK for Rust](https://github.com/azure/azure-sdk-for-rust).
It supports [Azure Blob Storage](https://docs.microsoft.com/azure/storage/blobs/storage-blobs-overview).

## Example

```rust no_run

use azure_core::error::{ErrorKind, ResultExt};
use azure_storage::prelude::*;
use azure_storage_blobs::prelude::*;
use futures::stream::StreamExt;

#[tokio::main]
async fn main() -> azure_core::Result<()> {
    let file_name = "azure_sdk_for_rust_stream_test.txt";

    // First we retrieve the account name and access key from environment variables.
    let account = std::env::var("STORAGE_ACCOUNT").expect("missing STORAGE_ACCOUNT");
    let access_key = std::env::var("STORAGE_ACCESS_KEY").expect("missing STORAGE_ACCOUNT_KEY");
    let container = std::env::var("STORAGE_CONTAINER").expect("missing STORAGE_CONTAINER");
    let blob_name = std::env::var("STORAGE_BLOB_NAME").expect("missing STORAGE_BLOB_NAME");

    let storage_credentials = StorageCredentials::access_key(account.clone(), access_key);
    let blob_client = ClientBuilder::new(account, storage_credentials).blob_client(&container, blob_name);

    blob_client.put_block_blob("hello world").content_type("text/plain").await?;

    let mut result: Vec<u8> = vec![];

    // The stream is composed of individual calls to the get blob endpoint
    let mut stream = blob_client.get().into_stream();
    while let Some(value) = stream.next().await {
        let mut body = value?.data;
        // For each response, we stream the body instead of collecting it all
        // into one large allocation.
        while let Some(value) = body.next().await {
            let value = value?;
            result.extend(&value);
        }
    }

    println!("result: {:?}", result);

    Ok(())
}

```

License: MIT
