# Investigation Notes — Lab 101: C2 Infrastructure Timeline Investigation

## 1. Investigation Overview

This investigation examines controlled PowerShell HTTP activity on a Windows endpoint to determine how process, network, and event-log evidence can be assembled into a defensible timeline.

The investigation uses a local HTTP listener and a client request as a safe simulation of C2-like communication. The focus is process-to-network correlation, timestamp validation, and the distinction between an observed HTTP exchange and a confirmed malicious C2 channel.

## 2. Host and User Baseline

The investigation workspace was created at:

`C:\C2TimelineLab\Evidence`

The investigation start time was recorded as `09 October 2026 05:53:24`.

| Field | Observed value |
|---|---|
| Hostname | `DESKTOP-9MMM37V` |
| Operating system | Windows Pro |
| OS build | `26200` |
| PowerShell version | `7.6.6` |
| User | `desktop-9mmm37v\dell` |
| Sysmon service | Running |
| Sysmon version | `15.21` |

The host baseline establishes the environment in which the controlled test was conducted. The user context identifies the account associated with the investigation session.

## 3. Listener Initialization

A PowerShell `System.Net.HttpListener` object was created and started.

The captured prefix was:

`http://127.0.0`

The listener reported that it was active at `10/09/2026 05:57:48`. A subsequent check returned `True` for `$Listener.IsListening`.

The listener process was recorded as:

| Field | Value |
|---|---|
| Process name | `pwsh` |
| PID | `3720` |
| Executable | PowerShell 7 |
| Process start time | `09-10-2026 05:53:11` |
| Listener initialization | `09-10-2026 05:57:48` |

The process start time predates listener initialization, which is consistent with the listener being started from an already running PowerShell session.

**Evidence limitation:** the listener prefix shown in the captured output does not include the documented port `8080`. The evidence file `C2-Test-Parameters.txt` records `127.0.0.1`, port `8080`, and HTTP as the intended test parameters. These values must not be treated as proof that the listener actually bound to that exact endpoint.

## 4. Controlled HTTP Request

The client-side output shows an HTTP request returning:

| Field | Value |
|---|---|
| Status | `200 OK` |
| Response content | `Controlled C2 Timeline Test` |
| Server header | `Microsoft-HTTPAPI/2.0` |
| Client timestamp | `2026-10-09T06:09:27.4196468+05:30` |
| Response date | `Fri, 09 Oct 2026 00:39:27 GMT` |

The returned body matches the message used in the listener response code. This supports the conclusion that a successful HTTP exchange occurred with a service that returned the controlled response.

However, the captured client command uses:

`http://127.0.0`

The intended test parameters specify `127.0.0.1:8080`. The successful response therefore cannot be attributed conclusively to the intended destination and port from the available screenshot alone.

The client-side timestamp and server response date are approximately consistent when converted to UTC, but they are not sufficient to establish the identity of the listening process or the exact destination port.

## 5. Process Creation Telemetry

Sysmon Event ID 1 recorded the creation of a PowerShell 7 process.

| Field | Value |
|---|---|
| Event ID | `1` |
| Event type | Process Create |
| Process ID | `30916` |
| Image | `pwsh.exe` |
| File version | `7.6.6.500` |
| Event time | `2026-10-09 00:36:29.726 UTC` |
| Host | `DESKTOP-9MMM37V` |

The event confirms that a PowerShell process was created. The supplied evidence does not include a complete command line or a matching network event that ties PID `30916` directly to the successful HTTP exchange.

A process-creation event must not be interpreted as network attribution by itself.

## 6. DNS Query Telemetry

Sysmon Event ID 22 recorded a DNS query with the following details:

| Field | Value |
|---|---|
| Event ID | `22` |
| Process ID | `30916` |
| Image | `pwsh.exe` |
| Query name | `DESKTOP-9MMM37V` |
| Query status | `0` |
| UTC timestamp | `2026-10-09 00:38:49.332 UTC` |

The query results contain host-related addresses, including addresses associated with the local system and VMware network interfaces.

This is hostname-resolution activity, not evidence of a query to a known C2 domain. The relationship between this event and the successful HTTP exchange is unconfirmed.

The supplied Event Viewer screenshot also shows several Sysmon Event ID 22 entries. Without examining their full details and timestamps, they should not be treated as separate C2 indicators.

## 7. TCP Connection Validation

The following query was executed:

```powershell
Get-NetTCPConnection |
Where-Object {
    $_.RemoteAddress -eq "127.0.0.1" -and
    $_.RemotePort -eq 8080
} |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
```

No matching rows were returned.

This means no connection matching those filters was visible in that particular snapshot. It does not prove that a connection never occurred. Short-lived HTTP connections may close before a later snapshot is collected.

A stronger validation would capture TCP state while the request is in progress and inspect Sysmon Event ID 3 for the exact destination, process ID, and timestamp.

## 8. Wazuh Correlation

A Wazuh record for agent `001` and host `DESKTOP-9MMM37V` showed an event containing:

`data.win.eventdata.ipAddress = 127.0.0.1`

The supplied fields do not identify this as the controlled HTTP connection. The record includes authentication-related fields, so it must not be reclassified as HTTP or C2 telemetry without inspecting its full event ID, event provider, and message.

Wazuh can support the investigation by correlating Sysmon process and network events, but only when the event fields establish a relationship to the activity under review.

## 9. Evidence Assessment

| Question | Assessment |
|---|---|
| Was the investigation workspace created? | Confirmed |
| Was Sysmon running? | Confirmed |
| Was a PowerShell listener started? | Confirmed |
| Was the listener configured on the intended port `8080`? | Not conclusively established |
| Was an HTTP response received? | Confirmed |
| Did the response contain the controlled message? | Confirmed |
| Was a PowerShell process-creation event observed? | Confirmed |
| Was a hostname DNS query observed? | Confirmed |
| Was a matching Sysmon Event ID 3 established? | Not established |
| Was a matching TCP connection present in the snapshot? | No |
| Was the successful HTTP exchange attributed to PID `30916`? | Not established |
| Was malicious C2 activity established? | No |

## 10. Conclusion

The evidence confirms a controlled HTTP response and relevant PowerShell endpoint activity. It also shows that Sysmon process-creation and DNS-query events were available for investigation. However, the intended listener destination, successful request URL, and expected network telemetry are not sufficiently aligned in the supplied evidence to establish a complete process-to-network chain.

The correct finding is **controlled C2-like HTTP activity observed, with destination and process attribution incomplete**. Further testing should verify the exact listener prefix, capture the request URL and active TCP connection, and correlate a matching Sysmon Event ID 3 or equivalent network record before stronger conclusions are made.
