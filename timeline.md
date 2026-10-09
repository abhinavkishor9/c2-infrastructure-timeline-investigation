# Timeline — Lab 101: C2 Infrastructure Timeline Investigation

## Investigation Details

| Field | Value |
|---|---|
| Host | `DESKTOP-9MMM37V` |
| User | `desktop-9mmm37v\dell` |
| Workspace | `C:\C2TimelineLab\Evidence` |
| Shell | PowerShell 7.6.6 |
| Sysmon version | 15.21 |
| Intended destination | `127.0.0.1:8080` |
| Protocol | HTTP |

## Event Timeline

| Local time (UTC+05:30) | Event | Evidence source | Assessment |
|---|---|---|---|
| 05:53:11 | Listener PowerShell process started | `Get-Process` output | Confirmed; PID `3720` |
| 05:53:24 | Investigation start time recorded | `Investigation-Time.txt` | Confirmed |
| 05:57:48 | HTTP listener reported started | PowerShell output | Confirmed; exact configured endpoint requires verification |
| 05:57 onward | Listener state checked | `$Listener.IsListening` | Returned `True` |
| 06:01:43 | Additional investigation timestamp recorded | `Get-Date` output | Confirmed |
| 06:06:29.726 | PowerShell process created | Sysmon Event ID 1, UTC `00:36:29.726` | Confirmed; PID `30916` |
| 06:06:29–06:06:34 | Additional process-creation and file-creation events displayed | Sysmon Event Viewer screenshot | Events observed; not individually attributed to the HTTP exchange |
| 06:08:47 | Sysmon Event ID 22 displayed in Event Viewer | Event Viewer screenshot | Event observed; full event details not supplied |
| 06:09:27.4196468 | HTTP client output timestamp recorded | PowerShell output | Confirmed |
| 06:09:27 local, approximately | HTTP request returned `200 OK` | `Invoke-WebRequest` output | Successful response confirmed; intended destination and port not conclusively established |
| 06:08:49 local, approximately | Hostname query event timestamp | Sysmon Event ID 22, UTC `00:38:49.332` | Query for `DESKTOP-9MMM37V`; relationship to HTTP request unconfirmed |
| After request | TCP query for `127.0.0.1:8080` returned no matching rows | `Get-NetTCPConnection` output | Point-in-time negative observation |
| During investigation | Wazuh record contained `127.0.0.1` | Wazuh document | Observed; not established as the controlled HTTP connection |

## Timestamp Notes

- The investigation start time and process/listener timestamps were captured in local time.
- Sysmon event details use UTC timestamps.
- The client timestamp `2026-10-09T06:09:27.4196468+05:30` corresponds to `2026-10-09 00:39:27.4196468 UTC`.
- The HTTP response header reports `Fri, 09 Oct 2026 00:39:27 GMT`.
- The Sysmon Event ID 22 timestamp `2026-10-09 00:38:49.332 UTC` converts to `06:08:49.332` local time.
- Event Viewer timestamps may have less precision than the detailed event record.
- The order of events in this table is a reconstruction from the supplied screenshots. It is not proof that every event belongs to one process or one HTTP session.

## Evidence Gaps

1. The intended destination is documented as `127.0.0.1:8080`, but the captured listener prefix and client URL are shown as `http://127.0.0`.
2. No matching TCP connection was visible when the connection query was executed.
3. The supplied evidence does not establish a Sysmon Event ID 3 record for the controlled HTTP request.
4. The Sysmon Event ID 1 record for PID `30916` is not directly correlated with the successful HTTP response.
5. The DNS event relates to the hostname `DESKTOP-9MMM37V`; attribution to the HTTP exchange is unconfirmed.
6. The Wazuh record containing `127.0.0.1` has not been established as the controlled HTTP connection.

## Timeline Conclusion

The investigation confirms that a PowerShell HTTP request received a successful response and that the endpoint generated PowerShell process-creation and DNS-query telemetry. However, the available evidence does not establish a complete process-to-network chain for `127.0.0.1:8080`.

The final classification is **controlled C2-like HTTP activity with incomplete destination and process attribution**. No malicious C2 infrastructure or malicious behavior has been established by the evidence reviewed.
