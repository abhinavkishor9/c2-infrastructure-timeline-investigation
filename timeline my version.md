# Timeline

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

