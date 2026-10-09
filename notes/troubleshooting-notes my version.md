# Troubleshooting Notes

## 1. HTTP Request Returned "Connection Refused"

### Symptom

The initial `Invoke-WebRequest` attempt failed with:

`No connection could be made because the target machine actively refused it.`

### Explanation

At the time of the initial request, no service was accepting connections at the requested endpoint. The listener may not have been running, may have stopped, or may have been bound to a different prefix or port.

### Recommended checks

Verify whether a listener is active:

```powershell
Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue |
Select-Object LocalAddress, LocalPort, OwningProcess
```

Inspect the owning process:

```powershell
Get-Process -Id <PID>
```

Replace `<PID>` with the actual process ID.

Confirm the listener's exact prefix and keep the listener running while sending a request from a separate PowerShell window.

## 2. `GetContext()` Returned a Null Value

### Symptom

The response code generated errors involving `$Context` and `$Response`.

### Explanation

The later code attempted to use a context that was not available. A valid request context is returned only after a listener has started and a request has been accepted. If the earlier request failed, the subsequent response code cannot operate on a valid context.

### Recommended approach

Run the listener lifecycle in one script:

1. Create the listener.
2. Add the exact URL prefix.
3. Start the listener.
4. Wait for a request.
5. Read the returned context.
6. Send the HTTP response.
7. Close the response and listener.

Check that `$Context` is not null before accessing its properties.

## 3. Listener Prefix and Port Do Not Match the Documented Parameters

### Observation

The evidence file records the intended destination as `127.0.0.1:8080`, but the listener prefix shown in the screenshot is:

`http://127.0.0`

The successful client command also shows:

`http://127.0.0`

### Impact

The screenshots do not conclusively demonstrate that the listener and client used the intended endpoint `127.0.0.1:8080`.

### Resolution

Use the same explicit prefix in both the listener and client configuration:

```powershell
$Listener = [System.Net.HttpListener]::new()
$Listener.Prefixes.Add("http://127.0.0.1:8080/")
$Listener.Start()
```

From a second PowerShell window:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8080/test" -UseBasicParsing
```

Verify the actual configured prefix and the complete request URI in the new evidence. Do not retroactively change the historical record.

## 4. `Get-NetTCPConnection` Returned No Results

### Observation

The query filtered for remote address `127.0.0.1` and remote port `8080`, but returned no rows.

### Explanation

`Get-NetTCPConnection` displays connections present at the time of the query. A short-lived HTTP connection may already be closed. A query that filters only on a remote address and port may also miss a listener or a connection recorded with different endpoint values.

### Resolution

Check the listener state separately:

```powershell
Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue
```

During a controlled request, inspect active connections:

```powershell
Get-NetTCPConnection -ErrorAction SilentlyContinue |
Where-Object {
    $_.LocalPort -eq 8080 -or $_.RemotePort -eq 8080
} |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
```

If no connection appears, record the result as a point-in-time observation. Use Sysmon Event ID 3 or other retained network telemetry to investigate past activity.

## 5. Sysmon Event ID 1 Does Not Prove Network Activity

### Observation

A Sysmon Event ID 1 record identified `pwsh.exe`, PID `30916`.

### Explanation

Event ID 1 records process creation. It does not independently establish that the process generated an HTTP request or connected to a destination.

### Resolution

Inspect the full event, including:

- Process ID and Process GUID
- Parent Process ID and Parent Process GUID
- Image and command line
- User
- UTC timestamp

Then search for a network event with a matching process identity and destination. Prefer Process GUID and timestamp correlation where available rather than relying on process names alone.

## 6. Sysmon Event ID 22 Shows a Hostname Query

### Observation

The recorded query name was `DESKTOP-9MMM37V`, and the process was `pwsh.exe`.

### Explanation

A hostname query is not evidence of communication with a C2 domain. It may result from normal host resolution or another local operation.

### Resolution

Inspect the complete event and determine whether its query name, timestamp, and process context relate to the controlled HTTP request. Do not label unrelated hostname-resolution activity as C2.

## 7. Wazuh Contains `127.0.0.1`, but Attribution Is Unclear

### Observation

A Wazuh record contained `data.win.eventdata.ipAddress = 127.0.0.1`.

### Explanation

An IP address appearing in an event does not establish that the event represents an HTTP connection. The supplied record also includes authentication-related fields.

### Resolution

Inspect the complete Wazuh document, including:

- `agent.id`
- `agent.name`
- `data.win.system.channel`
- `data.win.system.eventID`
- `data.win.system.providerName`
- `data.win.eventdata`
- `@timestamp`

Correlate the event with the intended endpoint, process, port, and test interval. Do not classify it as a network event without supporting fields.

## 8. Client and Event Timestamps Use Different Time Zones

### Observation

The client timestamp contains the `+05:30` offset, while Sysmon timestamps are shown in UTC.

### Explanation

The timestamps use different time representations. Comparing them without normalization may produce an incorrect event order.

### Resolution

Preserve the original timestamps and normalize them to UTC when building the timeline. The client time `2026-10-09T06:09:27.4196468+05:30` corresponds to `2026-10-09 00:39:27.4196468 UTC`.

Do not infer exact causality from rounded Event Viewer timestamps when more precise timestamps are available in the event details.

## 9. Missing Sysmon Event ID 3

### Observation

The supplied evidence does not establish a Sysmon Event ID 3 record matching the intended HTTP request.

### Explanation

The event may not have been generated, retained, ingested, or found by the query. The available evidence does not establish which explanation applies.

### Resolution

Verify the Sysmon configuration and search the Sysmon Operational log for Event ID 3 within the test interval. Examine the full event for the process image, process ID, destination IP, destination port, and UTC timestamp.

If no matching event is found, document the visibility gap. Do not conclude that the HTTP request did not happen.

