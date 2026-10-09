# Lab 101 — C2 Infrastructure Timeline Investigation

## Overview

This lab demonstrates how a DFIR analyst reconstructs a timeline of controlled command-and-control (C2)-like network activity using Windows process telemetry, HTTP request evidence, Sysmon events, TCP connection checks, and Wazuh endpoint data.

The investigation uses a local PowerShell HTTP listener and a separate PowerShell client to generate controlled HTTP activity. The objective is to correlate process creation, listener initialization, HTTP communication, and available endpoint telemetry into a defensible timeline.

The investigation follows a core DFIR principle: **follow the evidence, not the assumption**. A successful HTTP request or a connection to a particular IP address does not independently establish malicious command-and-control activity.

## Objectives

- Establish a documented Windows endpoint baseline.
- Record the investigation start time, host identity, and user context.
- Verify that Sysmon is running and identify its installed version.
- Initialize a controlled HTTP listener using PowerShell.
- Record the listener process and initialization time.
- Generate a controlled HTTP request from a separate PowerShell session.
- Record the HTTP response and associated timestamps.
- Examine Sysmon Event ID 1 for process creation evidence.
- Examine Sysmon Event ID 3 for network connection evidence.
- Review Sysmon Event ID 22 for relevant DNS query activity.
- Investigate available TCP connection information and process ownership.
- Correlate relevant endpoint telemetry in Wazuh.
- Reconstruct a timeline using observed timestamps and documented actions.
- Separate directly observed evidence from expected but unconfirmed events.
- Document telemetry gaps without treating missing events as proof of inactivity.
- Distinguish controlled C2-like activity from confirmed malicious C2.

## Lab Environment

| Component | Details |
|---|---|
| Host | `DESKTOP-9MMM37V` |
| Operating system | Windows Pro, build `26200` |
| User context | `desktop-9mmm37v\dell` |
| Shell | PowerShell 7.6.6 |
| Sysmon | Version 15.21 |
| Sysmon service | Running |
| Wazuh agent | `001` |
| Wazuh endpoint | `DESKTOP-9MMM37V` |
| Intended test destination | `127.0.0.1:8080` |
| Protocol | HTTP |
| Listener process | PowerShell 7 (`pwsh.exe`) |

## Investigation Scenario

An analyst is asked to reconstruct a sequence of PowerShell-related network events that resemble a basic C2 communication pattern. The investigation uses a locally hosted HTTP listener and a controlled client request instead of real malicious infrastructure.

The analyst records the host baseline, starts the listener, identifies the listener process, and generates an HTTP request from a separate PowerShell session. The available evidence is then examined for process creation, network connection, DNS query, and Wazuh ingestion records.

The investigation must establish which events are directly supported by evidence and which remain unconfirmed. In particular, the successful HTTP response demonstrates that an HTTP exchange occurred, but the available screenshots do not conclusively prove that the exchange used the documented destination port or that Sysmon recorded the corresponding network connection.

## Key Findings

| Investigation item | Finding |
|---|---|
| Investigation workspace | Created |
| Host baseline | Recorded |
| User context | Recorded |
| Sysmon service | Running |
| Sysmon version | 15.21 |
| Listener process | `pwsh.exe`, PID `3720` |
| Listener start time | `09-10-2026 05:57:48` |
| Listener status | `True` when checked |
| HTTP response | Status `200 OK` |
| HTTP response content | `Controlled C2 Timeline Test` |
| Documented test port | `8080` |
| Successful request destination | Command shows `http://127.0.0`; full endpoint and port attribution remain unresolved |
| TCP connection snapshot | No matching connection returned by the supplied filters |
| Sysmon Event ID 1 | PowerShell process creation observed |
| Sysmon Event ID 3 | Matching network connection not established from the supplied evidence |
| Sysmon Event ID 22 | A hostname query for `DESKTOP-9MMM37V` was observed; attribution to the HTTP exchange is not established |
| Wazuh | Endpoint telemetry observed, but the supplied record does not establish the controlled HTTP connection |
| Malicious C2 | Not established |

## Important Evidence

### Process Creation

A Sysmon Event ID 1 record identifies a PowerShell 7 process:

- Process ID: `30916`
- Image: `pwsh.exe`
- File version: `7.6.6.500`
- Event timestamp: `2026-10-09 00:36:29.726 UTC`
- Host: `DESKTOP-9MMM37V`

This establishes that the process was created. It does not independently prove that this process generated the successful HTTP request.

### HTTP Communication

The client output records:

- HTTP status: `200 OK`
- Response content: `Controlled C2 Timeline Test`
- Client-side timestamp: `2026-10-09T06:09:27.4196468+05:30`
- HTTP response date: `Fri, 09 Oct 2026 00:39:27 GMT`

The command shown in the evidence uses `http://127.0.0`. The documented intended destination is `127.0.0.1:8080`. Because these details do not conclusively match, the successful HTTP exchange cannot be attributed to the intended destination without further verification.

### Network Telemetry

The supplied `Get-NetTCPConnection` queries returned no matching connection for remote address `127.0.0.1` and remote port `8080`.

These commands provide a point-in-time view of connections. A completed HTTP connection may no longer be present when the query runs, so an empty result does not prove that no connection occurred.

### DNS Telemetry

Sysmon Event ID 22 records a query for `DESKTOP-9MMM37V` from a PowerShell process with PID `30916`.

The recorded query results include host-related IPv6 addresses and addresses associated with local interfaces. This event is not evidence of a DNS lookup for an external C2 domain, and its relationship to the successful HTTP request has not been established.

## Investigation Conclusion

The lab successfully recorded a controlled HTTP response and documented PowerShell process activity on the endpoint. Sysmon was running, and both process-creation and DNS-query events were present. However, the supplied evidence does not establish a complete process-to-network chain for the intended `127.0.0.1:8080` destination. The HTTP request URL, listener configuration, TCP snapshot, and event timestamps require further correlation before a precise destination and process attribution can be claimed.

The activity is therefore classified as **controlled C2-like HTTP activity with incomplete endpoint network attribution**. No evidence supplied in this investigation establishes malicious command-and-control infrastructure or malicious behavior.

## Evidence Handling

Evidence files are stored under:

`C:\C2TimelineLab\Evidence`

Key files include:

- `Investigation-Time.txt`
- `Host-Baseline.txt`
- `User-Context.txt`
- `C2-Test-Parameters.txt`
- `C2-Listener-Process.txt`

Preserve the original outputs and record any additional tests separately. Do not replace an earlier observation with a later result without documenting the change.

## Skills Demonstrated

- Windows endpoint investigation
- PowerShell process analysis
- Sysmon event analysis
- Network telemetry validation
- HTTP activity investigation
- Wazuh endpoint correlation
- Timeline reconstruction
- Evidence-based classification
- Telemetry gap documentation
