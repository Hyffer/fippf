# Test the network path between curl and mock SOCKS5 server

import subprocess
import json
import sys
import traceback

def fqdn(hostname):
    if not hostname.endswith("."):
        return hostname + "."
    return hostname

def test_with_curl(*args):
    domain = "google.com"
    path = "/test?hello=world"

    result = subprocess.run(
        [
            "curl",
            *args,
            f"http://{domain}{path}"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0, \
        f"curl failed: {result.stderr}"

    response = json.loads(result.stdout)

    # Assertions
    # Response from the mock server
    assert fqdn(response["target_host"]) == fqdn(domain), \
        f"response: {json.dumps(response, indent=2)}\nexpected target_host to be \"{domain}\""
    assert response["target_port"] == 80, \
        f"response: {json.dumps(response, indent=2)}\nexpected target_port to be 80"
    assert response["http_method"] == "GET", \
        f"response: {json.dumps(response, indent=2)}\nexpected http_method to be \"GET\""
    assert response["http_path"] == path, \
        f"response: {json.dumps(response, indent=2)}\nexpected http_path to be \"{path}\""

    assert "client" in response, \
        f"response: {json.dumps(response, indent=2)}\nmissing client field"
    assert "headers" in response, \
        f"response: {json.dumps(response, indent=2)}\nmissing headers field"
    assert fqdn(response["headers"].get("Host")) == fqdn(domain), \
        f"response: {json.dumps(response, indent=2)}\nexpected headers.Host to be \"{domain}\""


def run_test(*args):
    try:
        test_with_curl(*args)
        return 0

    except Exception:
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(run_test(*sys.argv[1:]))
