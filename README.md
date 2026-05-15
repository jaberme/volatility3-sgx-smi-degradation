# Volatility 3 SGX/SMI Degradation Triage Plugin

`sgx_smi_degradation.py` is a defensive Volatility 3 plugin for Linux memory investigations involving Intel SGX environments where the forensic hypothesis is not to read enclave memory, but to identify whether an enclave may have been degraded, influenced, or surrounded by suspicious activity originating outside the enclave boundary.

The plugin focuses on SGX aware memory triage, SMM/SMI related degradation indicators, CHIPSEC based platform evidence, and SMI counter timelines collected during acquisition.

## Purpose

Intel SGX is designed so that enclave contents cannot be directly inspected from normal operating system memory. This plugin therefore does not attempt to read EPC contents and does not claim to prove SMM compromise by itself.

Instead, it helps investigators reconstruct the observable ecosystem around SGX execution by correlating:

* SGX related process mappings.
* ENCLU and ENCLS instruction patterns.
* SGX runtime, driver, ECALL and OCALL strings.
* EPC like blind spots represented as all 0xFF pages in some memory acquisitions.
* CHIPSEC findings related to SMM, SMRAM, SPI, BIOS write protection and firmware configuration.
* SMI counter bursts that may suggest abnormal SMI activity or repeated enclave interruption.

The objective is to support forensic triage, hypothesis generation and evidence correlation in investigations where SGX, SMM, SMI and firmware trust boundaries are relevant.

## What the plugin does

The plugin produces a Volatility 3 `TreeGrid` with the following fields:

| Field | Meaning |
|------|---------|
| Scope | Whether the evidence comes from process memory, CHIPSEC output or SMI timeline data |
| PID | Process identifier, when applicable |
| Process | Linux process name |
| Object | VMA, CHIPSEC module or platform object |
| Evidence | Indicators found by the plugin |
| Score | Heuristic score assigned to the finding |
| Confidence | LOW, MEDIUM or HIGH confidence |
| Interpretation | Investigator oriented explanation of the finding |

## Installation

Copy the plugin into the Linux plugin directory of your Volatility 3 installation:

```bash
cp sgx_smi_degradation.py volatility3/volatility3/plugins/linux/
```

Then run Volatility 3 as usual.

## Basic usage

```bash
python3 vol.py -f mem.raw linux.sgx_smi_degradation.SgxSmiDegradation
```

## Extended usage with auxiliary evidence

```bash
python3 vol.py -f mem.raw linux.sgx_smi_degradation.SgxSmiDegradation \
    --max-vma-read 1048576 \
    --scan-memory \
    --chipsec-report file:///path/to/chipsec_report.json \
    --smi-timeline file:///path/to/smi_timeline.csv
```

## Parameters

| Parameter | Description |
|----------|-------------|
| `--scan-memory` | Scans readable process VMAs for SGX related instruction patterns and strings |
| `--max-vma-read` | Maximum number of bytes read from each VMA during heuristic scanning |
| `--min-ff-pages` | Minimum number of all 0xFF pages required to report an EPC like blind spot |
| `--chipsec-report` | Optional CHIPSEC JSON, text or console log collected during acquisition |
| `--smi-timeline` | Optional CSV or text file containing SMI counter samples |
| `--smi-burst-threshold` | Delta threshold used to flag SMI bursts |

## Auxiliary evidence formats

### CHIPSEC report

The plugin accepts CHIPSEC JSON, text output or collected console logs. It searches for suspicious findings in modules related to SMM, SMRR, SMM DMA, BIOS SMI, SMM code checks, SPI locking, BIOS write protection and UEFI image scanning.

### SMI timeline

The SMI timeline may be a CSV or text file containing timestamps and numeric SMI counter values.

Example:

```csv
timestamp,cpu,total_smi
2026-05-15T12:00:00,0,12033
2026-05-15T12:00:01,0,12390
```

The plugin estimates SMI bursts by calculating counter deltas and comparing them with the configured threshold.

## Interpretation model

This plugin should be used as a triage and correlation tool. It does not provide absolute proof of compromise.

A HIGH confidence result should be interpreted as a strong reason to continue forensic analysis, not as a final attribution. In particular, SMI bursts, CHIPSEC failures or SGX related memory artifacts must be correlated with acquisition context, platform firmware state, PCR values, SPI configuration, SMRAM protection, microcode level and the activity timeline of the suspected enclave process.

## Limitations

This plugin:

* Does not read EPC contents.
* Does not bypass SGX protections.
* Does not prove SMM compromise by itself.
* Does not replace CHIPSEC, firmware analysis or platform attestation.
* Uses heuristic scoring and should be interpreted by a qualified analyst.

## Defensive use

The plugin is intended for:

* Memory forensics.
* Incident response.
* SGX related DFIR.
* Firmware trust boundary assessment.
* Research into enclave degradation and SMM/SMI side effects.
* Training scenarios involving protected execution environments.

## Suggested citation

If you use this plugin in research, training or public material, please cite it as:

```text
José Antonio Álvarez Bermejo, Volatility 3 SGX/SMI Degradation Triage Plugin, 2026.
```

## License

Apache License 2.0.

## Disclaimer

This tool is provided for defensive security research, forensic triage and incident response. Findings must be validated with independent evidence before drawing conclusions about compromise, persistence or platform manipulation.
