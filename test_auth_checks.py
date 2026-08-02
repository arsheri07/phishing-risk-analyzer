import dkim
from auth_checks import parse_authentication_results_header, verify_dkim_signature


def _generate_real_test_keypair():
    """The hardcoded key above is a placeholder shape - actual tests
    generate a real throwaway keypair at runtime with openssl, since a
    valid RSA key can't just be typed out by hand."""
    import subprocess
    import tempfile
    import os

    tmpdir = tempfile.mkdtemp()
    priv_path = os.path.join(tmpdir, "priv.pem")
    pub_path = os.path.join(tmpdir, "pub.pem")

    subprocess.run(["openssl", "genrsa", "-out", priv_path, "1024"],
                    capture_output=True, check=True)
    subprocess.run(["openssl", "rsa", "-in", priv_path, "-pubout", "-out", pub_path],
                    capture_output=True, check=True)

    with open(priv_path, "rb") as f:
        priv = f.read()
    with open(pub_path, "rb") as f:
        pub_pem = f.read()

    pub_b64 = "".join(pub_pem.decode().split("\n")[1:-2])
    return priv, pub_b64


def test_parse_authentication_results_all_pass():
    header = "mx.google.com; spf=pass; dkim=pass; dmarc=pass"
    result = parse_authentication_results_header(header)
    assert result.spf == "pass"
    assert result.dkim == "pass"
    assert result.dmarc == "pass"


def test_parse_authentication_results_missing_header():
    result = parse_authentication_results_header("")
    assert result.spf == "none"
    assert result.dkim == "none"
    assert result.dmarc == "none"


def test_parse_authentication_results_mixed():
    header = "mx.google.com; spf=fail smtp.mailfrom=evil.com; dkim=none"
    result = parse_authentication_results_header(header)
    assert result.spf == "fail"
    assert result.dkim == "none"
    assert result.dmarc == "none"  # not present in header at all


def test_dkim_verification_passes_for_untampered_signed_email():
    private_key, pub_b64 = _generate_real_test_keypair()

    body = b"From: test@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\nHello world.\r\n"
    signed_headers = dkim.sign(message=body, selector=b"test", domain=b"example.com", privkey=private_key)
    full_email = signed_headers + body

    def mock_dns(domain, timeout=5):
        return f"v=DKIM1; k=rsa; p={pub_b64}"

    result = dkim.verify(full_email, dnsfunc=mock_dns)
    assert result is True


def test_dkim_verification_fails_for_tampered_email():
    private_key, pub_b64 = _generate_real_test_keypair()

    body = b"From: test@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\nHello world.\r\n"
    signed_headers = dkim.sign(message=body, selector=b"test", domain=b"example.com", privkey=private_key)
    full_email = signed_headers + body

    tampered_email = full_email.replace(b"Hello world.", b"Send money now.")

    def mock_dns(domain, timeout=5):
        return f"v=DKIM1; k=rsa; p={pub_b64}"

    result = dkim.verify(tampered_email, dnsfunc=mock_dns)
    assert result is False
