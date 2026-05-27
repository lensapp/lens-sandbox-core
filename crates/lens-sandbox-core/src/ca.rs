use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Tracks which CA certs have been installed (by PEM hash) to avoid duplicates.
static INSTALLED_CA_CERTS: Mutex<Option<HashSet<u64>>> = Mutex::new(None);

const CA_BUNDLE_PATH: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Install a CA PEM certificate into the system trust store.
/// Idempotent — same PEM installed twice is a no-op.
pub fn install_ca_cert(pem: &str) {
    install_ca_cert_to(pem, CA_BUNDLE_PATH);
}

fn install_ca_cert_to(pem: &str, ca_bundle_path: &str) {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    pem.hash(&mut hasher);
    let hash = hasher.finish();

    let mut guard = INSTALLED_CA_CERTS.lock().unwrap();
    let set = guard.get_or_insert_with(HashSet::new);
    if !set.insert(hash) {
        tracing::debug!("CA cert already installed, skipping");
        return;
    }
    drop(guard);

    if write_ca_cert(pem, ca_bundle_path).is_err() {
        let mut guard = INSTALLED_CA_CERTS.lock().unwrap();
        if let Some(set) = guard.as_mut() {
            set.remove(&hash);
        }
    }
}

fn write_ca_cert(pem: &str, ca_bundle_path: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut f = OpenOptions::new()
        .append(true)
        .open(ca_bundle_path)
        .map_err(|e| {
            tracing::error!("failed to open {ca_bundle_path} for appending: {e}");
            e
        })?;
    writeln!(f, "\n{pem}").map_err(|e| {
        tracing::error!("failed to append CA cert to {ca_bundle_path}: {e}");
        e
    })?;
    tracing::info!("proxy CA cert installed into {ca_bundle_path}");
    Ok(())
}

#[cfg(test)]
pub(crate) fn reset_installed_certs() {
    *INSTALLED_CA_CERTS.lock().unwrap() = None;
}

/// Ephemeral CA — generates a CA key pair on construction, signs domain certs on demand.
/// The CA private key lives only in process memory and dies with the container.
pub struct EphemeralCa {
    ca_cert: rcgen::Certificate,
    ca_cert_der: CertificateDer<'static>,
    ca_key: KeyPair,
    /// PEM representation for installing into the system trust store.
    ca_cert_pem: String,
    /// Cache of signed domain certs (domain -> (cert_chain, private_key)).
    domain_cache: RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>,
}

impl EphemeralCa {
    /// Generate a new ephemeral CA. Call once on sandbox startup.
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Lens Sandbox CA");

        let ca_cert = params.self_signed(&key_pair)?;
        let ca_cert_pem = ca_cert.pem();
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        Ok(Self {
            ca_cert,
            ca_cert_der,
            ca_key: key_pair,
            ca_cert_pem,
            domain_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Get the CA certificate as PEM for installing into the system trust store.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Get or generate a TLS certificate for a domain, signed by this CA.
    /// Results are cached for the process lifetime.
    pub fn certified_key_for_domain(
        &self,
        hostname: &str,
    ) -> Result<Arc<rustls::sign::CertifiedKey>, Box<dyn std::error::Error>> {
        // Check cache first
        {
            let cache = self.domain_cache.read().unwrap();
            if let Some(key) = cache.get(hostname) {
                return Ok(key.clone());
            }
        }

        // Generate domain key pair
        let domain_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

        let mut params = CertificateParams::new(vec![hostname.to_string()])?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname);

        let cert = params.signed_by(&domain_key, &self.ca_cert, &self.ca_key)?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivatePkcs8KeyDer::from(domain_key.serialize_der());

        let signing_key =
            rustls::crypto::ring::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(key_der))?;

        let certified_key = Arc::new(rustls::sign::CertifiedKey::new(
            vec![cert_der, self.ca_cert_der.clone()],
            signing_key,
        ));

        // Cache it
        {
            let mut cache = self.domain_cache.write().unwrap();
            cache.insert(hostname.to_string(), certified_key.clone());
        }

        Ok(certified_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both tests below manipulate the shared `INSTALLED_CA_CERTS` global via
    /// `reset_installed_certs()`. Running them in parallel is unsound: one
    /// test's reset can clear the other test's hash mid-run, causing a
    /// previously-skipped install to write again. Serialize via this mutex.
    static CA_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn install_ca_cert_is_idempotent() {
        let _guard = CA_TEST_LOCK.lock().unwrap();
        reset_installed_certs();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca-certificates.crt");
        std::fs::write(&path, "").unwrap();

        let pem = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----";
        let path_str = path.to_str().unwrap();

        install_ca_cert_to(pem, path_str);
        install_ca_cert_to(pem, path_str); // should be skipped (same PEM)

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.matches("BEGIN CERTIFICATE").count(), 1);

        reset_installed_certs();
    }

    #[test]
    fn install_ca_cert_allows_multiple_different_certs() {
        let _guard = CA_TEST_LOCK.lock().unwrap();
        reset_installed_certs();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca-certificates.crt");
        std::fs::write(&path, "").unwrap();

        let path_str = path.to_str().unwrap();
        install_ca_cert_to(
            "-----BEGIN CERTIFICATE-----\nCA1\n-----END CERTIFICATE-----",
            path_str,
        );
        install_ca_cert_to(
            "-----BEGIN CERTIFICATE-----\nCA2\n-----END CERTIFICATE-----",
            path_str,
        );

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.matches("BEGIN CERTIFICATE").count(), 2);
        assert!(contents.contains("CA1"));
        assert!(contents.contains("CA2"));

        reset_installed_certs();
    }
}
