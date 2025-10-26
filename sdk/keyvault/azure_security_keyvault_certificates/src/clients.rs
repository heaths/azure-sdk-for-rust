// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

pub use crate::generated::clients::*;
use crate::models::{
    CertificateClientBeginCreateCertificateOptions, CertificateClientCreateCertificateOptions,
    CertificateClientGetCertificateOperationOptions, CertificateClientGetCertificateOptions,
    CertificateOperation, CreateCertificateParameters,
};
use azure_core::{
    error::ErrorKind,
    http::{
        headers::{RETRY_AFTER, RETRY_AFTER_MS, X_MS_RETRY_AFTER_MS},
        poller::{
            get_retry_after, Poller, PollerResult, PollerState, PollerStatus, StatusMonitor as _,
        },
        Body, RequestContent, Url,
    },
    tracing, Result,
};

impl CertificateClient {
    /// Creates a new certificate and returns a [`Poller<CertificateOperation>`] to monitor the status.
    ///
    /// If this is the first version, the certificate resource is created. This operation requires the certificates/create permission.
    ///
    /// # Arguments
    ///
    /// * `certificate_name` - The name of the certificate. The value you provide may be copied globally for the purpose of running
    ///   the service. The value provided should not include personally identifiable or sensitive information.
    /// * `parameters` - The parameters to create a certificate.
    /// * `options` - Optional parameters for the request.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use azure_identity::DeveloperToolsCredential;
    /// use azure_security_keyvault_certificates::{
    ///     CertificateClient,
    ///     models::{CreateCertificateParameters, CertificatePolicy, X509CertificateProperties, IssuerParameters},
    /// };
    ///
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let credential = DeveloperToolsCredential::new(None)?;
    /// let client = CertificateClient::new(
    ///     "https://your-key-vault-name.vault.azure.net/",
    ///     credential.clone(),
    ///     None,
    /// )?;
    ///
    /// // Create a self-signed certificate.
    /// let policy = CertificatePolicy {
    ///     x509_certificate_properties: Some(X509CertificateProperties {
    ///         subject: Some("CN=DefaultPolicy".into()),
    ///         ..Default::default()
    ///     }),
    ///     issuer_parameters: Some(IssuerParameters {
    ///         name: Some("Self".into()),
    ///         ..Default::default()
    ///     }),
    ///     ..Default::default()
    /// };
    /// let body = CreateCertificateParameters {
    ///     certificate_policy: Some(policy),
    ///     ..Default::default()
    /// };
    ///
    /// // Wait for the certificate operation to complete and get the certificate.
    /// let certificate = client
    ///     .create_certificate("certificate-name", body.try_into()?, None)?
    ///     .await?
    ///     .into_body()?;
    ///
    /// # Ok(()) }
    /// ```
    #[tracing::function("KeyVault.createCertificate")]
    pub fn create_certificate(
        &self,
        certificate_name: &str,
        parameters: RequestContent<CreateCertificateParameters>,
        options: Option<CertificateClientCreateCertificateOptions<'_>>,
    ) -> Result<Poller<CertificateOperation>> {
        let options = options.unwrap_or_default().into_owned();
        let certificate_name = certificate_name.to_owned();
        let parameters: Body = parameters.into();
        let client = self.to_owned();

        Ok(Poller::from_callback(
            move |next_link: PollerState<Url>| {
                let options = options.clone();
                let certificate_name = certificate_name.clone();
                let parameters = parameters.clone();
                let client = client.to_owned();

                async move {
                    let method_options = options.method_options.clone();
                    let response = match next_link {
                        PollerState::Initial => {
                            let options =
                                CertificateClientBeginCreateCertificateOptions { method_options };
                            client
                                .begin_create_certificate(
                                    &certificate_name,
                                    parameters.into(),
                                    Some(options),
                                )
                                .await?
                        }
                        PollerState::More(_) => {
                            let options =
                                CertificateClientGetCertificateOperationOptions { method_options };
                            client
                                .get_certificate_operation(&certificate_name, Some(options))
                                .await?
                        }
                    };

                    let operation: CertificateOperation = response.body().json()?;
                    let retry_after = get_retry_after(
                        response.headers(),
                        &[RETRY_AFTER_MS, X_MS_RETRY_AFTER_MS, RETRY_AFTER],
                        &options.poller_options,
                    );

                    Ok(match operation.status() {
                        PollerStatus::InProgress => {
                            let next = match operation.id {
                                Some(id) => id.parse()?,
                                None => {
                                    return Err(azure_core::Error::new(
                                        ErrorKind::Other,
                                        "missing operation link",
                                    ))
                                }
                            };
                            PollerResult::InProgress {
                                response,
                                retry_after,
                                next,
                            }
                        }
                        PollerStatus::Succeeded => {
                            let options = CertificateClientGetCertificateOptions {
                                certificate_version: None,
                                method_options: options.method_options,
                            };
                            PollerResult::Succeeded {
                                response,
                                target: Box::new(move || {
                                    Box::pin(async move {
                                        let certificate = client
                                            .get_certificate(&certificate_name, Some(options))
                                            .await?;
                                        Ok(certificate)
                                    })
                                }),
                            }
                        }
                        _ => PollerResult::Done { response },
                    })
                }
            },
            None,
        ))
    }

    pub(crate) fn to_owned(&self) -> CertificateClient {
        CertificateClient {
            api_version: self.api_version.clone(),
            endpoint: self.endpoint.clone(),
            pipeline: self.pipeline.clone(),
            tracer: self.tracer.clone(),
        }
    }
}
