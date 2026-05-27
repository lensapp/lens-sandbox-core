use tokio::process::Command;

pub const CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Set CA-related env vars for a child process so common runtimes and CLIs trust
/// the system CA bundle. The proxy CA cert is appended to this file later via
/// policy message, but the path is stable.
pub fn apply_ca_env(cmd: &mut Command) {
    cmd.env("SSL_CERT_FILE", CA_BUNDLE)
        .env("REQUESTS_CA_BUNDLE", CA_BUNDLE)
        .env("NODE_EXTRA_CA_CERTS", CA_BUNDLE)
        .env("CURL_CA_BUNDLE", CA_BUNDLE)
        .env("GIT_SSL_CAINFO", CA_BUNDLE);
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRINT_CA_ENV_CMD: &str = "printf '%s|%s|%s|%s|%s' \"$SSL_CERT_FILE\" \"$REQUESTS_CA_BUNDLE\" \"$NODE_EXTRA_CA_CERTS\" \"$CURL_CA_BUNDLE\" \"$GIT_SSL_CAINFO\"";

    #[tokio::test]
    async fn apply_ca_env_sets_expected_vars() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(PRINT_CA_ENV_CMD);
        cmd.env_clear();
        apply_ca_env(&mut cmd);

        let output = cmd.output().await.expect("command should run");
        assert!(output.status.success());

        let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
        let expected = format!("{0}|{0}|{0}|{0}|{0}", CA_BUNDLE);
        assert_eq!(stdout, expected);
    }

    #[tokio::test]
    async fn apply_ca_env_overrides_existing_values() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(PRINT_CA_ENV_CMD);
        cmd.env_clear();
        cmd.env("SSL_CERT_FILE", "/tmp/wrong-ssl.pem")
            .env("REQUESTS_CA_BUNDLE", "/tmp/wrong-requests.pem")
            .env("NODE_EXTRA_CA_CERTS", "/tmp/wrong-node.pem")
            .env("CURL_CA_BUNDLE", "/tmp/wrong-curl.pem")
            .env("GIT_SSL_CAINFO", "/tmp/wrong-git.pem");
        apply_ca_env(&mut cmd);

        let output = cmd.output().await.expect("command should run");
        assert!(output.status.success());

        let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
        let expected = format!("{0}|{0}|{0}|{0}|{0}", CA_BUNDLE);
        assert_eq!(stdout, expected);
    }
}
