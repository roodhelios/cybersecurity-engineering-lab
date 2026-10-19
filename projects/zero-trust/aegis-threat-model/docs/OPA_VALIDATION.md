# Native OPA validation

On October 19, 2026, the local conformance command ran the eight reviewed fixtures
against the real OPA executable and returned `matched_count: 8` with no mismatches.
The combined signed-request tests also ran with native policy evaluation. No OPA
server, cloud resource, or third-party target was contacted by policy evaluation.
This is recorded local evidence produced with Codex assistance, not a manual lab
result or a production security claim.

## Reproduce

From the project directory, use Python 3.11 or newer in an isolated environment:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

For Linux amd64, acquire the exact tested binary from the
[official OPA 1.21.2 release](https://github.com/open-policy-agent/opa/releases/tag/v1.21.2):

```bash
curl --fail --location https://github.com/open-policy-agent/opa/releases/download/v1.21.2/opa_linux_amd64_static \
  --output /tmp/opa-1.21.2
printf '%s  %s\n' '830ab11f61ffec760b5e19db0d7ad02bf037e13f5ef4d665faeaf17632177527' '/tmp/opa-1.21.2' | sha256sum --check
chmod 755 /tmp/opa-1.21.2
/tmp/opa-1.21.2 version
```

Choose a fresh trusted download path, and stop if the download or checksum check
fails. Do not commit the binary. Other architectures need their own release artifact
and digest; they were not tested in this run.

```bash
PYTHONPATH=src python -m aegis_threat_model.opa_conformance_cli \
  --opa /tmp/opa-1.21.2 --rego policy/aegis.rego --data policy/data.json --cases policy/cases.json
PYTHONPATH=src python -m aegis_threat_model.authorization_cli \
  --request examples/signed-request.json --credential examples/credential.json \
  --policy policy/data.json --risk-score 20 --now 1789686000 \
  --opa /tmp/opa-1.21.2 --rego policy/aegis.rego
```

The first command reports eight matches. The second returns `effect: allow`,
`reason: authorized`, `stage: policy`, and `policy_engine: opa`. To run installed-OPA
tests, place a verified executable named `opa` on PATH before test discovery:

```bash
python -m unittest discover -s tests -v
```

The recorded run used Python 3.12.14 and an executable named `opa` on PATH. All 60
project tests passed, with zero skips. The existing native conformance test ran, as
did eight combined native authorization regressions covering allow, role denial,
step-up, replay, signatures, clock bounds, and invalid risk input. Separate failure
tests verify that rejected signatures do not call the evaluator and a missing native
binary cannot fall back to the oracle or print success.

## Exact inputs

| Artifact | SHA-256 |
| --- | --- |
| Official `opa_linux_amd64_static` | `830ab11f61ffec760b5e19db0d7ad02bf037e13f5ef4d665faeaf17632177527` |
| `policy/aegis.rego` | `55add10d11baa1e78916da01db655b06162df6c46629a81de7d620bc15bd40e4` |
| `policy/data.json` | `93aa82f38fd5ba11ecee6b3a0f7f0906738ba193ce2aebb440367cb86f9c800a` |
| `policy/cases.json` | `593399f720ff5e95d890afd466639e30a4fedf5b34278233d70ac0c849e952cd` |

The official binary reported version 1.21.2, Rego v1, Linux amd64, and build commit
`3f7474e6b3c631821d8aac25ca444f7e75a56483-dirty`. The `dirty` suffix is the published
binary's own version output, not a claim that this repository was used to build it.
Its SHA-256 matched the digest published in the release metadata. That comparison
does not establish reproducible build provenance or eliminate dependency risk.

The repository policy uses local data only. Native mode does not sandbox arbitrary
Rego builtins or untrusted policy files. These cases do not establish OPA server
authentication, distributed replay protection, live service availability, exhaustive
policy correctness, or validation of the separate Aegis portfolio repository.
