# c2-infrastructure-timeline-investigation
## Overview
A C2 Infrastructure Timeline Investigation reconstructs the sequence of events surrounding suspected command-and-control activity. Instead of treating a single network connection as proof of C2, the analyst correlates multiple artifacts such as process creation, network connections, DNS activity, file creation, PowerShell execution, and Wazuh/Sysmon telemetry.

The investigation should answer:

What process initiated the activity, when did it occur, what destination was contacted, what happened before and after the connection, and is there enough evidence to classify the activity as confirmed C2, suspicious network behavior, or benign controlled activity?

This lab demonstrates how a DFIR analyst reconstructs a timeline of controlled command-and-control (C2)-like network activity using Windows process telemetry, HTTP request evidence, Sysmon events, TCP connection checks, and Wazuh endpoint data.

The investigation uses a local PowerShell HTTP listener and a separate PowerShell client to generate controlled HTTP activity. The objective is to correlate process creation, listener initialization, HTTP communication, and available endpoint telemetry into a defensible timeline.

The investigation follows a core DFIR principle: **follow the evidence, not the assumption**. A successful HTTP request or a connection to a particular IP address does not independently establish malicious command-and-control activity.

## Lab Objectives

- Establish a documented baseline of the Windows endpoint, current user, PowerShell environment, and investigation workspace.
- Verify the operational status and version of Sysmon before beginning the investigation.
- Configure a controlled local HTTP listener to simulate C2-like communication without contacting external infrastructure.
- Record the listener's process ID, executable path, process start time, initialization time, and configured URL prefix.
- Generate controlled HTTP requests from a separate PowerShell session.
- Capture HTTP request details, response status, response content, and relevant timestamps.
- Verify that the actual client URL matches the intended destination IP address and port.
- Examine Sysmon Event ID 1 to identify PowerShell process creation and establish process context.
- Investigate Sysmon Event ID 3 for network connection evidence associated with the controlled HTTP activity.
- Examine Sysmon Event ID 22 for relevant DNS queries and determine whether they relate to the investigation.
- Inspect active TCP connections and identify owning processes where connection state permits.
- Correlate process identifiers, destination addresses, destination ports, and timestamps across available evidence sources.
- Use Wazuh endpoint telemetry to investigate whether relevant Windows and Sysmon events were ingested.
- Distinguish authentication events containing IP addresses from actual network connection events.
- Normalize local timestamps and UTC timestamps to establish a consistent event sequence.
- Construct a chronological timeline covering listener initialization, process activity, HTTP communication, and post-test validation.
- Compare the intended test parameters against the actual listener configuration and recorded client request.
- Identify discrepancies between the expected destination and the endpoint values observed in the evidence.
- Document missing or unmatched telemetry without assuming that the corresponding activity did not occur.
- Separate directly observed events from inferred relationships and unresolved attribution questions.
- Determine whether the available evidence supports process-to-network attribution for the controlled HTTP exchange.
- Distinguish benign laboratory-generated C2-like communication from suspicious activity and confirmed malicious command-and-control.
- Produce a reproducible investigation record that clearly communicates findings, evidence limitations, and the final assessment.
  
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

## Lab Scenario

A Windows endpoint is selected for a digital forensics investigation after PowerShell activity and HTTP communication are identified during a controlled security exercise. The objective is to reconstruct the sequence of events and determine whether the available evidence establishes a relationship between process execution and network activity resembling command-and-control (C2) communication.

The investigation uses a locally hosted HTTP listener and a separate PowerShell client to generate controlled requests. Before generating the traffic, the analyst documents the endpoint, user context, Sysmon status, listener configuration, and intended destination. Process information and timestamps are collected to establish a baseline for subsequent correlation.

The investigation examines several sources of evidence:
- **Process telemetry:** Sysmon Event ID 1 to identify PowerShell processes and their execution context.
- **Network telemetry:** Sysmon Event ID 3 and TCP connection information to investigate destination addresses, ports, and process attribution.
- **DNS telemetry:** Sysmon Event ID 22 to determine whether relevant hostname-resolution activity occurred.
- **HTTP evidence:** Client output, response status, response content, and recorded timestamps.
- **Endpoint correlation:** Wazuh records to determine whether relevant Sysmon events were ingested and can be associated with the controlled activity.

A key investigative challenge is establishing whether the observed events belong to the same activity. The successful HTTP response demonstrates that an HTTP exchange occurred, but the recorded URL, intended destination port, process identifiers, and available network telemetry must be compared before attributing the communication to a specific process or endpoint.

The analyst must also account for differences between local time and UTC, short-lived connections that may disappear before a TCP snapshot is collected, and missing or incomplete event records. An empty query result is documented as **no matching telemetry observed**, not as proof that the activity never occurred.

The investigation concludes by producing a chronological timeline that separates confirmed observations from unresolved relationships. The final assessment must determine whether the evidence supports process-to-network attribution, identify any telemetry gaps, and distinguish intentionally generated C2-like communication from confirmed malicious command-and-control activity. No event or relationship should be classified as malicious without sufficient supporting evidence.

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

