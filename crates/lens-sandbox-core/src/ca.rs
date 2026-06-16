use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

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

/// Upper bound on cached per-host MITM certs. A guest under a permissive or
/// wildcard policy can iterate distinct SNIs; without a bound each forces a
/// fresh keygen+sign and a permanent entry, growing RSS without limit. The
/// cap keeps memory flat (a few hundred P-256 certs is small) while still
/// covering the working set of any realistic workload.
const CERT_CACHE_CAPACITY: usize = 256;

/// Capacity-bounded LRU of signed domain certs. On overflow the
/// least-recently-used entry is evicted; a subsequent miss regenerates it.
///
/// Recency is tracked with a monotonic logical clock stamped onto each entry,
/// rather than a recency list. A cache hit (the per-handshake hot path) is then
/// O(1) — it just bumps the entry's tick — and the only O(n) scan is the
/// least-recently-used search, which runs solely on an over-capacity insert.
struct DomainCertCache {
    entries: HashMap<String, CacheEntry>,
    /// Logical clock; incremented on every access so the smallest `last_used`
    /// is the least-recently-used entry. u64 is effectively unwrappable here
    /// (2^64 accesses), but `wrapping_add` keeps it panic-free regardless.
    clock: u64,
    capacity: usize,
}

struct CacheEntry {
    cert: Arc<rustls::sign::CertifiedKey>,
    last_used: u64,
}

impl DomainCertCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            clock: 0,
            capacity,
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock = self.clock.wrapping_add(1);
        self.clock
    }

    fn get(&mut self, hostname: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let tick = self.tick();
        let entry = self.entries.get_mut(hostname)?;
        entry.last_used = tick;
        Some(entry.cert.clone())
    }

    fn insert(&mut self, hostname: String, cert: Arc<rustls::sign::CertifiedKey>) {
        let last_used = self.tick();
        let is_new = self
            .entries
            .insert(hostname, CacheEntry { cert, last_used })
            .is_none();
        // Only a genuinely new key can grow the map past capacity; overwriting
        // an existing host just refreshes its cert and recency.
        if is_new && self.entries.len() > self.capacity {
            self.evict_lru();
        }
    }

    /// Drop the entry with the smallest `last_used`. O(n) over the map, but
    /// reached only when an insert overflows capacity — never on a cache hit.
    fn evict_lru(&mut self) {
        if let Some(victim) = self
            .entries
            .iter()
            .min_by_key(|(_host, entry)| entry.last_used)
            .map(|(host, _entry)| host.clone())
        {
            self.entries.remove(&victim);
        }
    }
}

/// Normalize an SNI/hostname for use as a cache key and certificate SAN: DNS
/// names are case-insensitive (RFC 4343) and an absolute name's trailing dot is
/// not significant, so fold both away. Without this, case/trailing-dot
/// permutations of one allowed host (`Host`, `HOST.`, `host`) would each take a
/// distinct cache slot, letting a guest thrash the bounded cache and evict the
/// legitimate working set.
fn normalize_host(hostname: &str) -> String {
    hostname
        .strip_suffix('.')
        .unwrap_or(hostname)
        .to_ascii_lowercase()
}

/// Ephemeral CA — generates a CA key pair on construction, signs domain certs on demand.
/// The CA private key lives only in process memory and dies with the container.
pub struct EphemeralCa {
    ca_cert: rcgen::Certificate,
    ca_cert_der: CertificateDer<'static>,
    ca_key: KeyPair,
    /// PEM representation for installing into the system trust store.
    ca_cert_pem: String,
    /// Capacity-bounded LRU of signed domain certs (domain -> cert_chain+key).
    domain_cache: Mutex<DomainCertCache>,
}

impl EphemeralCa {
    /// Generate a new ephemeral CA. Call once on sandbox startup.
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        // Strict OpenSSL verification (X509_V_FLAG_X509_STRICT) requires a CA to
        // carry keyUsage with keyCertSign; without it the chain is rejected.
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
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
            domain_cache: Mutex::new(DomainCertCache::new(CERT_CACHE_CAPACITY)),
        })
    }

    /// Get the CA certificate as PEM for installing into the system trust store.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Get or generate a TLS certificate for a domain, signed by this CA.
    /// Results are cached in a bounded LRU (see [`CERT_CACHE_CAPACITY`]); an
    /// entry may be evicted under cache pressure and regenerated on a later
    /// request, so callers must not assume a stable `Arc` across calls.
    pub fn certified_key_for_domain(
        &self,
        hostname: &str,
    ) -> Result<Arc<rustls::sign::CertifiedKey>, Box<dyn std::error::Error>> {
        let hostname = normalize_host(hostname);

        // Check cache first
        {
            let mut cache = self.domain_cache.lock().unwrap();
            if let Some(key) = cache.get(&hostname) {
                return Ok(key);
            }
        }

        // Generate domain key pair
        let domain_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

        let mut params = CertificateParams::new(vec![hostname.clone()])?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname.clone());
        // Strict OpenSSL verification (X509_V_FLAG_X509_STRICT, enabled by some
        // Python TLS stacks) rejects a non-self-signed leaf without an AKI; emit
        // one referencing the CA's subject key identifier, plus the keyUsage and
        // serverAuth EKU a TLS server leaf is expected to carry.
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

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
            let mut cache = self.domain_cache.lock().unwrap();
            cache.insert(hostname, certified_key.clone());
        }

        Ok(certified_key)
    }

    #[cfg(test)]
    fn cache_len(&self) -> usize {
        self.domain_cache.lock().unwrap().entries.len()
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
    fn distinct_domains_under_cap_all_cache() {
        // Up to the cap, every distinct domain is retained — a second call
        // for the same domain returns the identical Arc (a cache hit, no
        // regeneration).
        let ca = EphemeralCa::new().unwrap();
        let mut keys = Vec::new();
        for i in 0..CERT_CACHE_CAPACITY {
            keys.push(
                ca.certified_key_for_domain(&format!("h{i}.example"))
                    .unwrap(),
            );
        }
        for (i, first) in keys.iter().enumerate() {
            let again = ca
                .certified_key_for_domain(&format!("h{i}.example"))
                .unwrap();
            assert!(
                Arc::ptr_eq(first, &again),
                "domain h{i} should still be cached (same Arc)"
            );
        }
        assert_eq!(ca.cache_len(), CERT_CACHE_CAPACITY);
    }

    #[test]
    fn cache_evicts_oldest_past_capacity_and_regenerates() {
        // Filling past the cap evicts the least-recently-used entry (the
        // first domain). Re-requesting it is a miss → a freshly generated
        // Arc, not the original.
        let ca = EphemeralCa::new().unwrap();
        let oldest = ca.certified_key_for_domain("oldest.example").unwrap();
        for i in 0..CERT_CACHE_CAPACITY {
            ca.certified_key_for_domain(&format!("h{i}.example"))
                .unwrap();
        }
        assert_eq!(
            ca.cache_len(),
            CERT_CACHE_CAPACITY,
            "cache must not grow past its capacity"
        );
        let regenerated = ca.certified_key_for_domain("oldest.example").unwrap();
        assert!(
            !Arc::ptr_eq(&oldest, &regenerated),
            "evicted domain must be regenerated as a new cert, not the original Arc"
        );
    }

    #[test]
    fn cache_hit_does_not_grow_or_regenerate() {
        // Repeated requests for one domain are hits: the cache stays at one
        // entry and hands back the same Arc every time.
        let ca = EphemeralCa::new().unwrap();
        let first = ca.certified_key_for_domain("repeat.example").unwrap();
        for _ in 0..50 {
            let again = ca.certified_key_for_domain("repeat.example").unwrap();
            assert!(Arc::ptr_eq(&first, &again));
        }
        assert_eq!(ca.cache_len(), 1);
    }

    #[test]
    fn recently_used_entry_survives_eviction() {
        // LRU, not FIFO: touching the oldest entry before overflow makes a
        // different entry the eviction victim.
        let ca = EphemeralCa::new().unwrap();
        let kept = ca.certified_key_for_domain("kept.example").unwrap();
        for i in 0..(CERT_CACHE_CAPACITY - 1) {
            ca.certified_key_for_domain(&format!("h{i}.example"))
                .unwrap();
        }
        // Touch "kept" so it's the most-recently-used, then overflow by one.
        let kept_touch = ca.certified_key_for_domain("kept.example").unwrap();
        assert!(Arc::ptr_eq(&kept, &kept_touch));
        ca.certified_key_for_domain("overflow.example").unwrap();

        let kept_after = ca.certified_key_for_domain("kept.example").unwrap();
        assert!(
            Arc::ptr_eq(&kept, &kept_after),
            "the recently-used entry must survive; h0 should have been evicted instead"
        );
    }

    #[test]
    fn host_normalization_dedups_case_and_trailing_dot() {
        // Case and a trailing dot are not significant in DNS names, so all
        // these variants must resolve to one cache entry and the same Arc —
        // otherwise a guest could thrash the bounded cache with permutations
        // of a single allowed host and evict the legitimate working set.
        let ca = EphemeralCa::new().unwrap();
        let base = ca.certified_key_for_domain("api.example").unwrap();
        for variant in ["API.EXAMPLE", "Api.Example.", "api.example."] {
            let again = ca.certified_key_for_domain(variant).unwrap();
            assert!(
                Arc::ptr_eq(&base, &again),
                "{variant} must hit the same cache entry as api.example"
            );
        }
        assert_eq!(ca.cache_len(), 1);
    }

    #[test]
    fn domain_leaf_carries_authority_key_identifier() {
        // Strict OpenSSL verification rejects a non-self-signed leaf that lacks
        // an AKI extension (`CERTIFICATE_VERIFY_FAILED: Missing Authority Key
        // Identifier`). The MITM leaf must carry one or those TLS stacks fail.
        let ca = EphemeralCa::new().unwrap();
        let ck = ca.certified_key_for_domain("api.anthropic.com").unwrap();
        let leaf = ck.cert[0].as_ref();
        // authorityKeyIdentifier OID 2.5.29.35, DER-encoded as `06 03 55 1D 23`.
        const AKI_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x23];
        assert!(
            leaf.windows(5).any(|w| w == AKI_OID),
            "leaf cert is missing the authorityKeyIdentifier extension"
        );
    }

    #[test]
    fn ca_carries_subject_key_identifier_for_the_aki_to_reference() {
        // The leaf's AKI points at the CA's SKI; without the SKI the chain
        // identifier linkage strict mode wants is broken.
        let ca = EphemeralCa::new().unwrap();
        let ck = ca.certified_key_for_domain("api.anthropic.com").unwrap();
        let ca_der = ck.cert[1].as_ref();
        // subjectKeyIdentifier OID 2.5.29.14, DER-encoded as `06 03 55 1D 0E`.
        const SKI_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x0E];
        assert!(
            ca_der.windows(5).any(|w| w == SKI_OID),
            "CA cert is missing the subjectKeyIdentifier extension"
        );
    }

    #[test]
    fn ca_carries_key_usage_extension() {
        // Strict OpenSSL fails the chain with "CA cert does not include key
        // usage extension" unless the CA advertises keyUsage (keyCertSign).
        let ca = EphemeralCa::new().unwrap();
        let ck = ca.certified_key_for_domain("api.anthropic.com").unwrap();
        let ca_der = ck.cert[1].as_ref();
        // keyUsage OID 2.5.29.15, DER-encoded as `06 03 55 1D 0F`.
        const KEY_USAGE_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x0F];
        assert!(
            ca_der.windows(5).any(|w| w == KEY_USAGE_OID),
            "CA cert is missing the keyUsage extension"
        );
    }

    #[test]
    fn domain_leaf_carries_extended_key_usage_server_auth() {
        // TLS verifiers expect a server leaf to advertise the serverAuth EKU.
        let ca = EphemeralCa::new().unwrap();
        let ck = ca.certified_key_for_domain("api.anthropic.com").unwrap();
        let leaf = ck.cert[0].as_ref();
        // extendedKeyUsage OID 2.5.29.37, DER-encoded as `06 03 55 1D 25`.
        const EKU_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x25];
        assert!(
            leaf.windows(5).any(|w| w == EKU_OID),
            "leaf cert is missing the extendedKeyUsage extension"
        );
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
