# malicious_nuclei_templates

This is a collection of malicious templates that can be used in projectdiscovery/nuclei to achieve some kind of security compromise.

# Templates

## rce-CVE-2021-21224.yaml

This is a RCE that exploited an outdated go-rod library of Nuclei, which runs an outdated unsandboxed version of Chromium when using the headless engine.
Changing the shellcode on the *shellcode* variable is possible. The default shellcode will run `touch /tmp/rce_on_nuclei`

Usage:
```bash
nuclei -t rce-CVE-2021-21224.yaml -headless
```

# References
- https://lude.rs/h4ck1ng/pwning_nuclei.html
