// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! The [`Recording`] and other types used in recorded tests.

// cspell:ignore csprng seedable
use crate::{
    proxy::{
        client::{
            Client, ClientAddSanitizerOptions, ClientRemoveSanitizersOptions,
            ClientSetMatcherOptions,
        },
        models::{SanitizerList, StartPayload, VariablePayload},
        policy::RecordingPolicy,
        Proxy, RecordingId,
    },
    Matcher, MockCredential, Sanitizer,
};
use azure_core::{
    base64,
    credentials::TokenCredential,
    error::ErrorKind,
    headers::{AsHeaders, HeaderName, HeaderValue},
    test::TestMode,
    ClientOptions, Header,
};
use azure_identity::DefaultAzureCredential;
use rand::{
    distributions::{Distribution, Standard},
    Rng, SeedableRng,
};
use rand_chacha::ChaCha20Rng;
use std::{
    borrow::Cow,
    cell::OnceCell,
    collections::HashMap,
    env,
    sync::{Arc, Mutex, OnceLock, RwLock},
};
use tracing::span::EnteredSpan;

/// Represents a playback or recording session using the [`Proxy`].
#[derive(Debug)]
pub struct Recording {
    test_mode: TestMode,
    // Keep the span open for our lifetime.
    #[allow(dead_code)]
    span: EnteredSpan,
    _proxy: Option<Arc<Proxy>>,
    client: Option<Client>,
    policy: OnceCell<Arc<RecordingPolicy>>,
    service_directory: String,
    recording_file: String,
    recording_assets_file: Option<String>,
    id: Option<RecordingId>,
    variables: RwLock<HashMap<String, Value>>,
    rand: OnceLock<Mutex<ChaCha20Rng>>,
}

impl Recording {
    /// Adds a [`Sanitizer`] to sanitize PII for the current test.
    pub async fn add_sanitizer<S>(&self, sanitizer: S) -> azure_core::Result<()>
    where
        S: Sanitizer,
        azure_core::Error: From<<S as AsHeaders>::Error>,
    {
        let Some(client) = &self.client else {
            return Ok(());
        };

        let options = ClientAddSanitizerOptions {
            recording_id: self.id.as_ref(),
            ..Default::default()
        };
        client.add_sanitizer(sanitizer, Some(options)).await
    }

    /// Gets a [`TokenCredential`] you can use for testing.
    ///
    /// # Panics
    ///
    /// Panics if the [`TokenCredential`] could not be created.
    pub fn credential(&self) -> Arc<dyn TokenCredential> {
        match self.test_mode {
            TestMode::Playback => Arc::new(MockCredential) as Arc<dyn TokenCredential>,
            _ => DefaultAzureCredential::new().map_or_else(
                |err| panic!("failed to create DefaultAzureCredential: {err}"),
                |cred| cred as Arc<dyn TokenCredential>,
            ),
        }
    }

    /// Instruments the [`ClientOptions`] to support recording and playing back of session records.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use azure_core_test::{recorded, TestContext};
    ///
    /// # struct MyClient;
    /// # #[derive(Default)]
    /// # struct MyClientOptions { client_options: azure_core::ClientOptions };
    /// # impl MyClient {
    /// #   fn new(endpoint: impl AsRef<str>, options: Option<MyClientOptions>) -> Self { todo!() }
    /// #   async fn invoke(&self) -> azure_core::Result<()> { todo!() }
    /// # }
    /// #[recorded::test]
    /// async fn test_invoke(ctx: TestContext) -> azure_core::Result<()> {
    ///     let recording = ctx.recording();
    ///
    ///     let mut options = MyClientOptions::default();
    ///     ctx.instrument(&mut options.client_options);
    ///
    ///     let client = MyClient::new("https://azure.net", Some(options));
    ///     client.invoke().await
    /// }
    /// ```
    pub fn instrument(&self, options: &mut ClientOptions) {
        if self.client.is_none() {
            return;
        }

        let policy = self
            .policy
            .get_or_init(|| {
                Arc::new(RecordingPolicy {
                    test_mode: self.test_mode,
                    host: self.client.as_ref().map(|c| c.endpoint().clone()),
                    recording_id: self.id.clone(),
                    ..Default::default()
                })
            })
            .clone();

        options.per_try_policies.push(policy);
    }

    /// Get random data from the OS or recording.
    ///
    /// This will always be the OS cryptographically secure pseudo-random number generator (CSPRNG) when running live.
    /// When recording, it will initialize from the OS CSPRNG but save the seed value to the recording file.
    /// When playing back, the saved seed value is read from the recording to reproduce the same sequence of random data.
    ///
    /// # Examples
    ///
    /// Generate a symmetric data encryption key (DEK).
    ///
    /// ```no_compile
    /// let dek: [u8; 32] = recording.random();
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the recording variables cannot be locked for reading or writing,
    /// or if the random seed cannot be encoded or decoded properly.
    ///
    pub fn random<T>(&self) -> T
    where
        Standard: Distribution<T>,
    {
        const NAME: &str = "RandomSeed";

        // Use ChaCha20 for a deterministic, portable CSPRNG.
        let rng = self.rand.get_or_init(|| match self.test_mode {
            TestMode::Live => ChaCha20Rng::from_entropy().into(),
            TestMode::Playback => {
                let variables = self
                    .variables
                    .read()
                    .map_err(read_lock_error)
                    .unwrap_or_else(|err| panic!("{err}"));
                let seed: String = variables
                    .get(NAME)
                    .map(Into::into)
                    .unwrap_or_else(|| panic!("random seed variable not set"));
                let seed = base64::decode(seed)
                    .unwrap_or_else(|err| panic!("failed to decode random seed: {err}"));
                let seed = seed
                    .first_chunk::<32>()
                    .unwrap_or_else(|| panic!("insufficient random seed variable"));

                ChaCha20Rng::from_seed(*seed).into()
            }
            TestMode::Record => {
                let rng = ChaCha20Rng::from_entropy();
                let seed = rng.get_seed();
                let seed = base64::encode(seed);

                let mut variables = self
                    .variables
                    .write()
                    .map_err(write_lock_error)
                    .unwrap_or_else(|err| panic!("{err}"));
                variables.insert(NAME.to_string(), Value::from(Some(seed), None));

                rng.into()
            }
        });

        let Ok(mut rng) = rng.lock() else {
            panic!("failed to lock RNG");
        };

        rng.gen()
    }

    /// Removes the list of sanitizers from the recording.
    ///
    /// You can find a list of default sanitizers in [source code](https://github.com/Azure/azure-sdk-tools/blob/main/tools/test-proxy/Azure.Sdk.Tools.TestProxy/Common/SanitizerDictionary.cs).
    pub async fn remove_sanitizers(&self, sanitizers: &[&str]) -> azure_core::Result<()> {
        let Some(client) = &self.client else {
            return Ok(());
        };

        let body = SanitizerList {
            sanitizers: Vec::from_iter(sanitizers.iter().map(|s| String::from(*s))),
        };
        let options = ClientRemoveSanitizersOptions {
            recording_id: self.id.as_ref(),
            ..Default::default()
        };
        client
            .remove_sanitizers(body.try_into()?, Some(options))
            .await?;

        Ok(())
    }

    /// Sets a [`Matcher`] to compare requests and/or responses.
    pub async fn set_matcher(&self, matcher: Matcher) -> azure_core::Result<()> {
        let Some(client) = &self.client else {
            return Ok(());
        };

        let options = ClientSetMatcherOptions {
            recording_id: self.id.as_ref(),
            ..Default::default()
        };
        client.set_matcher(matcher, Some(options)).await
    }

    /// Skip recording the request body, or the entire request and response until the [`SkipGuard`] is dropped.
    ///
    /// This only affects [`TestMode::Record`] mode and is intended for cleanup.
    /// When [`Recording::test_mode()`] is [`TestMode::Playback`] you should avoid sending those requests.
    pub fn skip(&self, skip: Skip) -> azure_core::Result<SkipGuard<'_>> {
        self.set_skip(Some(skip))?;
        Ok(SkipGuard(self))
    }

    /// Gets the current [`TestMode`].
    pub fn test_mode(&self) -> TestMode {
        self.test_mode
    }

    /// Gets a required variable from the environment or recording.
    pub fn var<K>(&self, key: K, options: Option<VarOptions>) -> String
    where
        K: AsRef<str>,
    {
        let key = key.as_ref();
        self.var_opt(key, options)
            .unwrap_or_else(|| panic!("{key} is not set"))
    }

    /// Gets an optional variable from the environment or recording.
    pub fn var_opt<K>(&self, key: K, options: Option<VarOptions>) -> Option<String>
    where
        K: AsRef<str>,
    {
        let key = key.as_ref();
        if self.test_mode == TestMode::Playback {
            let variables = self.variables.read().map_err(read_lock_error).ok()?;
            return variables.get(key).map(Into::into);
        }

        let value = self.env(key);
        if self.test_mode == TestMode::Live {
            return value;
        }

        let mut variables = self.variables.write().map_err(write_lock_error).ok()?;
        variables.insert(key.into(), Value::from(value.as_ref(), options));
        value
    }
}

impl Recording {
    pub(crate) fn new(
        test_mode: TestMode,
        span: EnteredSpan,
        proxy: Option<Arc<Proxy>>,
        client: Option<Client>,
        service_directory: &'static str,
        recording_file: String,
        recording_assets_file: Option<String>,
    ) -> Self {
        Self {
            test_mode,
            span,
            _proxy: proxy,
            client,
            policy: OnceCell::new(),
            service_directory: service_directory.into(),
            recording_file,
            recording_assets_file,
            id: None,
            variables: RwLock::new(HashMap::new()),
            rand: OnceLock::new(),
        }
    }

    fn env<K>(&self, key: K) -> Option<String>
    where
        K: AsRef<str>,
    {
        const AZURE_PREFIX: &str = "AZURE_";

        env::var_os(self.service_directory.clone() + "_" + key.as_ref())
            .or_else(|| env::var_os(key.as_ref()))
            .or_else(|| env::var_os(String::from(AZURE_PREFIX) + key.as_ref()))
            .and_then(|v| v.into_string().ok())
    }

    fn set_skip(&self, skip: Option<Skip>) -> azure_core::Result<()> {
        let Some(policy) = self.policy.get() else {
            return Ok(());
        };

        let mut options = policy
            .options
            .write()
            .map_err(|err| azure_core::Error::message(ErrorKind::Other, err.to_string()))?;
        options.skip = skip;

        Ok(())
    }

    /// Starts recording or playback.
    ///
    /// If playing back a recording, environment variable that were recorded will be reloaded.
    pub(crate) async fn start(&mut self) -> azure_core::Result<()> {
        let Some(client) = self.client.as_ref() else {
            // Assumes running live test.
            return Ok(());
        };

        let payload = StartPayload {
            recording_file: self.recording_file.clone(),
            recording_assets_file: self.recording_assets_file.clone(),
        };

        // TODO: Should RecordingId be used everywhere and models implement AsHeaders and FromHeaders?
        let recording_id = match self.test_mode {
            TestMode::Playback => {
                let result = client.playback_start(payload.try_into()?, None).await?;
                let mut variables = self.variables.write().map_err(write_lock_error)?;
                variables.extend(result.variables.into_iter().map(|(k, v)| (k, v.into())));

                result.recording_id
            }
            TestMode::Record => {
                client
                    .record_start(payload.try_into()?, None)
                    .await?
                    .recording_id
            }
            mode => panic!("{mode:?} not supported"),
        };
        self.id = Some(recording_id.parse()?);

        Ok(())
    }

    /// Stops the recording or playback.
    ///
    /// If recording, environment variables that were retrieved will be recorded.
    pub(crate) async fn stop(&self) -> azure_core::Result<()> {
        let Some(client) = self.client.as_ref() else {
            // Assumes running live test.
            return Ok(());
        };

        let Some(recording_id) = self.id.as_ref() else {
            // Do not return an error or we hide any test-proxy client or client under test error.
            return Ok(());
        };

        match self.test_mode {
            TestMode::Playback => client.playback_stop(recording_id.as_ref(), None).await,
            TestMode::Record => {
                let payload = {
                    let variables = self.variables.read().map_err(read_lock_error)?;
                    VariablePayload {
                        variables: HashMap::from_iter(
                            variables.iter().map(|(k, v)| (k.clone(), v.into())),
                        ),
                    }
                };
                client
                    .record_stop(recording_id.as_ref(), payload.try_into()?, None)
                    .await
            }
            mode => panic!("{mode:?} not supported"),
        }
    }
}

impl Drop for Recording {
    /// Stops the recording or playback.
    fn drop(&mut self) {
        futures::executor::block_on(self.stop()).unwrap_or_else(|err| panic!("{err}"));
    }
}

fn read_lock_error(_: impl std::error::Error) -> azure_core::Error {
    azure_core::Error::message(ErrorKind::Other, "failed to lock variables for read")
}

fn write_lock_error(_: impl std::error::Error) -> azure_core::Error {
    azure_core::Error::message(ErrorKind::Other, "failed to lock variables for write")
}

/// What to skip when recording to a file.
///
/// This only affects [`TestMode::Record`] mode and is intended for cleanup.
/// When [`Recording::test_mode()`] is [`TestMode::Playback`] you should avoid sending those requests.
#[derive(Debug)]
pub enum Skip {
    /// Skip recording only the request body.
    RequestBody,

    /// Skip recording both the request and response entirely.
    RequestResponse,
}

impl Header for Skip {
    fn name(&self) -> HeaderName {
        HeaderName::from_static("x-recording-skip")
    }

    fn value(&self) -> HeaderValue {
        match self {
            Self::RequestBody => HeaderValue::from_static("request-body"),
            Self::RequestResponse => HeaderValue::from_static("request-response"),
        }
    }
}

/// When the `SkipGuard` is dropped, recording requests and responses will begin again.
///
/// Returned from [`Recording::skip()`].
pub struct SkipGuard<'a>(&'a Recording);

impl Drop for SkipGuard<'_> {
    fn drop(&mut self) {
        if self.0.test_mode == TestMode::Record {
            let _ = self.0.set_skip(None);
        }
    }
}

/// Options for getting variables from a [`Recording`].
#[derive(Clone, Debug)]
pub struct VarOptions {
    /// Whether to sanitize the variable value with [`VarOptions::sanitize_value`].
    pub sanitize: bool,

    /// The value to use for sanitized variables.
    ///
    /// The default is "Sanitized".
    pub sanitize_value: Cow<'static, str>,
}

impl Default for VarOptions {
    fn default() -> Self {
        Self {
            sanitize: false,
            sanitize_value: Cow::Borrowed(crate::SANITIZED_VALUE),
        }
    }
}

#[derive(Debug)]
struct Value {
    value: String,
    sanitized: Option<Cow<'static, str>>,
}

impl Value {
    fn from<S>(value: Option<S>, options: Option<VarOptions>) -> Self
    where
        S: Into<String>,
    {
        Self {
            value: value.map_or_else(String::new, Into::into),
            sanitized: match options {
                Some(options) if options.sanitize => Some(options.sanitize_value.clone()),
                _ => None,
            },
        }
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self {
            value,
            sanitized: None,
        }
    }
}

impl From<&Value> for String {
    fn from(value: &Value) -> Self {
        value
            .sanitized
            .as_ref()
            .map_or_else(|| value.value.clone(), |v| v.to_string())
    }
}
