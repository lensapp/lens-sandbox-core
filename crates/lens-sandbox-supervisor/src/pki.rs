//! The certificates of one sandbox generation.

use std::collections::HashMap;

use lens_sandbox_core::channel::{self, ChannelTls, SUPERVISOR_NAME};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};

/// The supervisor leaf names only [`SUPERVISOR_NAME`] and each runtime leaf
/// only its container, so neither can act as the other. The CA key is not
/// kept, so nobody can add a leaf to the generation later.
pub struct ChannelPki {
    pub supervisor: ChannelTls,
    pub runtimes: HashMap<String, ChannelTls>,
}

impl ChannelPki {
    pub fn generate<'a>(
        containers: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, rcgen::Error> {
        let ca_key = KeyPair::generate()?;
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key)?;
        let leaf = |sans: Vec<SanType>, usage: ExtendedKeyUsagePurpose| {
            let key = KeyPair::generate()?;
            let mut params = CertificateParams::new(Vec::<String>::new())?;
            params.subject_alt_names = sans;
            params.extended_key_usages = vec![usage];
            let cert = params.signed_by(&key, &ca, &ca_key)?;
            Ok::<_, rcgen::Error>(ChannelTls {
                ca: ca.pem().into_bytes(),
                cert: cert.pem().into_bytes(),
                key: key.serialize_pem().into_bytes(),
            })
        };
        let supervisor = leaf(
            vec![SanType::DnsName(SUPERVISOR_NAME.try_into()?)],
            ExtendedKeyUsagePurpose::ServerAuth,
        )?;
        let runtimes = containers
            .into_iter()
            .map(|container| {
                let uri = SanType::URI(channel::container_uri(container).try_into()?);
                Ok((
                    container.to_string(),
                    leaf(vec![uri], ExtendedKeyUsagePurpose::ClientAuth)?,
                ))
            })
            .collect::<Result<_, rcgen::Error>>()?;
        Ok(Self {
            supervisor,
            runtimes,
        })
    }
}
