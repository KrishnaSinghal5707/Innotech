# Focused static IaC cryptographic configuration scanner

This opt-in pass inspects a small, explicit set of Dockerfile, ingress-nginx Ingress and Terraform TLS declarations. It does not discover deployed state or certify cryptographic/PQC readiness.

## Run

### Website

Start the dashboard with `python dashboard.py`, open its printed local URL, and select **IaC & Docker** under **Scan Configuration**. Enter a repository/configuration-file path inside this workspace, or click **Try IaC example (issue + unknown)**, then **Scan IaC & Docker**. Results open in **IaC & Docker Evidence**, with separate filters for issues, unknown settings, nonmatching settings and image references. File/line evidence, remediation, source links, coverage diagnostics, history and exports are available there. This scan mode never contacts the host field and runs the existing source pass as well when scanning a directory.

The API equivalent is `POST /api/scan` with `{"scan_type":"iac","repo":"docs/examples/iac_sample"}`. It retains the dashboard's workspace, Host and Origin restrictions. An HTTP 200 response means a report was produced; inspect its coverage and diagnostics for partial analysis.

### CLI

```powershell
python -m pip install -r requirements.txt
python main.py --repo path/to/repository --iac --no-color
python main.py --repo path/to/main.tf --iac --json report.json --output report.md
python main.py --repo docs/examples/iac_sample --iac --json sample.json
```

`--iac` requires `--repo`. With a directory, existing Python/JS source discovery still runs and the independent IaC pass adds its results. A single supported configuration file goes directly to the IaC pass. Without `--iac`, existing behavior is unchanged. `--quantum-only` applies to source-code detection; these opt-in IaC checks remain conventional configuration checks. Display filters (`--track`, `--min-severity`) retain the existing conventions.

CLI exit status follows the existing contract: **0** means analysis completed, including reports that contain issues; **1** means a failed/partial stage or unresolved configuration evidence; **2** means invalid CLI arguments. Check the findings as well as the exit code. The scanner writes a report even when unknown settings make analysis partial. Missing settings do not automatically become vulnerabilities.

## Exact supported rules

All five rules use the existing `Finding`, `RuleSet` and `RiskEngine` contracts. They are conventional, static, high-severity configuration rules. Rules are appended to a private copy of the selected ruleset only when `--iac` is enabled; an explicitly supplied rule with the same ID takes precedence. Runtime-worded TLS handshake rules are intentionally not used for configuration declarations.

| Rule ID | Exact supported trigger |
| --- | --- |
| `IAC_DOCKER_TLS_VERIFY_DISABLED` | Literal Dockerfile `ENV NODE_TLS_REJECT_UNAUTHORIZED=0`, or `ENV GIT_SSL_NO_VERIFY` with `true`, `yes`, `on` or `1` (case-insensitive Git boolean values). Supports assignment-list and legacy `ENV key value` syntax. |
| `IAC_INGRESS_LEGACY_TLS` | A supported Ingress's `nginx.ingress.kubernetes.io/proxy-ssl-protocols` explicitly includes `SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.0` or `TLSv1.1`. This is **upstream** TLS configuration, not the frontend protocol policy. |
| `IAC_INGRESS_WEAK_CIPHER` | `nginx.ingress.kubernetes.io/ssl-ciphers` (frontend) or `proxy-ssl-ciphers` (upstream) explicitly includes one of the weak tokens listed below in a simple colon-separated inclusion list. |
| `IAC_INGRESS_VERIFY_DISABLED` | `nginx.ingress.kubernetes.io/proxy-ssl-verify: "off"` with an explicitly declared `backend-protocol` of `HTTPS` or `GRPCS`. Missing/dynamic backend context stays unknown. |
| `IAC_AWS_LEGACY_TLS_POLICY` | An eligible Terraform `aws_lb_listener` / `aws_alb_listener` `ssl_policy`, or CloudFront viewer `minimum_protocol_version`, exactly matches the frozen legacy catalog below. No policy-prefix or version-name guesses. |

Findings include relative file path, source line, rule ID, allowlisted observed value, rationale, confidence, remediation and a primary-source link. Raw detection confidence represents certainty about a literal declaration; assessment confidence is independently computed by the existing engine. Neither is evidence of effective runtime behavior.

### Dockerfile subset

Recognized names: `Dockerfile`, `Dockerfile.*`, `*.dockerfile` (case-insensitive discovery). Literal `FROM` image references support registry/repository names, tags, SHA-256 digests, optional `--platform=...`, stage aliases and `scratch`. They are observations only. **No base image name, tag, digest or apparent age is used to infer PQC capability or its absence.** ARG expansion, mutable tag contents and image package inventories are not resolved.

Backslash continuations and ordinary quoted ENV values are supported. Nonstandard escape directives and heredocs produce partial coverage; heredoc bodies are not interpreted as Dockerfile instructions. RUN/CMD scripts are never executed or analyzed for TLS flags. The scanner records declarations in all stages; it does not calculate final image layers, environment inheritance/overrides, build targets or whether a setting is used by an installed application.

The environment rules are grounded in [Node's TLS environment setting](https://nodejs.org/api/cli.html#node_tls_reject_unauthorizedvalue) and [Git's certificate-verification configuration](https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpsslVerify). [Docker's Dockerfile reference](https://docs.docker.com/reference/dockerfile/) defines the syntax subset.

### Kubernetes subset

Plain single/multi-document YAML Ingress objects with `networking.k8s.io/v1` or `networking.k8s.io/v1beta1`. Only the four configuration annotations above and the supporting backend-protocol annotation are interpreted. These annotations are ingress-nginx-specific; the scanner does not resolve IngressClass objects, controller ownership/version, global ConfigMaps, TLS termination elsewhere, Secrets, certificate contents or inherited controller defaults. Annotation presence shows declared intent, not controller enforcement. In particular, there is no generic Ingress `ssl-protocols` annotation that this scanner treats as a frontend protocol setting.

Weak cipher tokens: `RC4`, `RC4-SHA`, `RC4-MD5`, `DES-CBC-SHA`, `DES-CBC3-SHA`, `NULL`, `eNULL`, `aNULL`, `EXP`, `EXPORT`.

Recognized nonmatching tokens: `ECDHE-RSA-AES128-GCM-SHA256`, `ECDHE-RSA-AES256-GCM-SHA384`, `ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-ECDSA-AES256-GCM-SHA384`, `ECDHE-RSA-CHACHA20-POLY1305`, `ECDHE-ECDSA-CHACHA20-POLY1305`.

Recognized nonmatching protocols: `TLSv1.2`, `TLSv1.3`. A literal list can produce a known weak-token finding alongside an unknown-token diagnostic. Templates and expressions involving cipher exclusion/reordering operators (`!`, `+`, `-`, `@`) are left unresolved; `!RC4` is never mistaken for enabling RC4. A nonmatching token is not proof of complete cipher safety or PQC readiness.

Primary controller semantics: [ingress-nginx annotations](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/).

### Terraform and exact AWS policy catalog

Native `.tf` source only, parsed as HCL2 without evaluating expressions. No Terraform command, provider, module, plan, state or variable-value file is invoked or read. `aws_lb_listener` and the `aws_alb_listener` alias require an explicit literal `protocol = "HTTPS"` or `"TLS"`; HTTP/TCP listeners are not assessed as TLS listeners. Dynamic or missing protocol/policy values remain unknown.

ELB legacy policies recognized as permitting TLS below 1.2:

- `ELBSecurityPolicy-2016-08`
- `ELBSecurityPolicy-TLS-1-1-2017-01`
- `ELBSecurityPolicy-TLS13-1-1-2021-06`
- `ELBSecurityPolicy-TLS13-1-0-2021-06`
- `ELBSecurityPolicy-TLS13-1-0-PQ-2025-09`

ELB policies recognized as not matching this legacy-protocol rule:

- `ELBSecurityPolicy-TLS-1-2-2017-01`
- `ELBSecurityPolicy-TLS-1-2-Ext-2018-06`
- `ELBSecurityPolicy-TLS13-1-2-2021-06`
- `ELBSecurityPolicy-TLS13-1-2-Res-2021-06`
- `ELBSecurityPolicy-TLS13-1-3-2021-06`
- `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`

These exact identities come from the documented [ALB](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html) and [NLB](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html) policy tables, reviewed 29 October 2026. Unknown, newer and unlisted identifiers stay unknown; even a name containing `PQ` is not proof that a client negotiates PQC.

For `aws_cloudfront_distribution.viewer_certificate`, custom-certificate context must be explicit (`cloudfront_default_certificate = false`, or a certificate-selector attribute when that flag is absent), and `ssl_support_method` must be literal `sni-only` or `vip`. A default CloudFront certificate makes the explicitly supplied minimum-policy field inapplicable to this rule; its default behavior is outside this catalog check. A dynamic certificate selection or SNI-only/SSLv3 combination is unknown, not a confirmed deployed weakness.

CloudFront legacy catalog: `SSLv3` (eligible `vip` context), `TLSv1`, `TLSv1_2016`, `TLSv1.1_2016`. Recognized nonmatching catalog: `TLSv1.2_2018`, `TLSv1.2_2019`, `TLSv1.2_2021`, `TLSv1.2_2025`, `TLSv1.3_2025`. See the [viewer policy table](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html) and [certificate applicability requirements](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ViewerCertificate.html).

Terraform block/resource labels are not emitted, only source positions and supported setting names. Provider defaults, classic ELB policies, origin TLS, generated/dynamic blocks, `.tf.json`, evaluated modules/locals/count/for_each and general provider schema validation are outside scope. The scanner does not determine whether any resource is instantiated or applied.

## Safety and coverage

- Maximum 256 KiB per input file, 1,000 supported candidate files per invocation. Only regular files inside the selected scope are read. Parent-traversal targets, symlinks and Windows junctions (including target ancestors) are rejected/skipped. No referenced path from a configuration file is followed.
- No repository code, shell commands, Terraform evaluation or YAML constructors execute. YAML uses safe node composition, rejects aliases, limits parser events to 10,000 and nesting to 48. HCL output is bounded to 10,000 syntax-tree nodes; Windows line endings and EOF without a newline are supported.
- Unreadable directories/files, oversized inputs, malformed/unsupported syntax and parser-dependency failures produce sanitized diagnostics and partial coverage. Parser exceptions and source excerpts are never printed. Unknown field values are represented as `<unresolved>` instead of echoing arbitrary values.
- `Secret` manifest payloads are not walked or exported. `.tfstate*` and `.tfvars` files are excluded before opening; unrelated YAML and unsupported file types are not claimed as security-reviewed. Terraform variables and unrelated Docker ENV values are never included in reports.
- The new pass emits only allowlisted enums/tokens and supported image references, file/line evidence and fixed explanatory strings. Existing shared output redaction remains in place.

The new module and rules are separate from existing scanners and the dashboard. CloudFormation is intentionally not included in this focused delivery. This is not full Kubernetes, Docker or Terraform security coverage, an authenticated runtime test, compliance certification, or a PQC support detector.

## Tests and sample report

```powershell
python -m py_compile iac_scanner.py iac_policies.py main.py scan_results.py
python -m unittest test_iac_scanner -v
python -m unittest discover -v
python main.py --repo docs/examples/iac_sample --iac --json docs/examples/iac_sample_report.json --output docs/examples/iac_sample_report.md
```

The last command intentionally exits **1**: the sample contains a documented legacy ELB policy and a second policy that depends on `var.security_policy`. The resulting [JSON report](examples/iac_sample_report.json) and [Markdown report](examples/iac_sample_report.md) show the issue alongside unknown evidence, with readiness undetermined.

See [IaC verification results](IAC_VERIFICATION.md) for actual commands, test counts and the host-specific symlink-test limitation.
