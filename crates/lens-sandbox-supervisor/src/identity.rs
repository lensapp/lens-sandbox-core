//! Which runtime a request comes from: the container that its client
//! certificate names.

use lens_sandbox_core::channel;
use tonic::Request;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo, UdsConnectInfo};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

pub(crate) fn container<T>(request: &Request<T>) -> Option<String> {
    let extensions = request.extensions();
    let certs = extensions
        .get::<TlsConnectInfo<TcpConnectInfo>>()
        .and_then(TlsConnectInfo::peer_certs)
        .or_else(|| {
            extensions
                .get::<TlsConnectInfo<UdsConnectInfo>>()
                .and_then(TlsConnectInfo::peer_certs)
        })?;
    container_of(certs.first()?)
}

/// A leaf that names more than one container names none.
fn container_of(der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let names = cert.subject_alternative_name().ok()??;
    let mut containers = names
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => channel::container_from_uri(uri),
            _ => None,
        });
    let container = containers.next()?;
    containers.next().is_none().then(|| container.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(uris: &[String]) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = uris
            .iter()
            .map(|uri| rcgen::SanType::URI(uri.clone().try_into().unwrap()))
            .collect();
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn a_leaf_names_its_container() {
        let der = leaf(&[channel::container_uri("agent")]);
        assert_eq!(container_of(&der).as_deref(), Some("agent"));
    }

    #[test]
    fn a_leaf_with_no_or_two_containers_names_none() {
        assert_eq!(container_of(&leaf(&[])), None);
        assert_eq!(container_of(&leaf(&["urn:other:agent".into()])), None);
        let two = [
            channel::container_uri("agent"),
            channel::container_uri("dockerd"),
        ];
        assert_eq!(container_of(&leaf(&two)), None);
        assert_eq!(container_of(b"not a certificate"), None);
    }
}
