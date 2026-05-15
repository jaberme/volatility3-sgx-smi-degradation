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
