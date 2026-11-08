# Network Traffic Security Investigation Report

*SOC Tier 1 | Offline PCAP Investigation | Evidence-based case study*

**Case:** Suspicious Multi-Stage Network Activity  
**Primary Host:** DESKTOP-L8C5GSJ (10.1.17.215)  
**Evidence Source:** Offline PCAP Analysis  
**Primary Tool:** Wireshark  
**Investigation Scope:** SOC Tier 1 Network Investigation  
**Assessment:** Suspicious Activity — Endpoint Compromise Not Confirmed  
**Recommended Action:** Escalation to SOC Tier 2  

## 1. Executive Summary

An offline network traffic investigation identified suspicious activity involving the internal Windows host DESKTOP-L8C5GSJ (10.1.17.215) and multiple external endpoints.

The investigation identified HTTP delivery of a VBScript-like component containing a PowerShell download command, followed by requests for obfuscated PowerShell scripts and transfers of executable-format objects from 5.252.153.241.

Additional observations included repeated HTTP requests to a fixed resource path, a request containing a startup shortcut success message, and encrypted TLS communications with 45.125.66.32 over TCP port 2917.

The observed behavior is consistent with potentially coordinated, multi-stage suspicious activity involving script-based delivery, additional payload transfers, and possible persistence or command-and-control functionality.

However, the available network evidence does not independently confirm execution of the transferred content, successful persistence, malware infection, or command-and-control activity.

Based on the combination of correlated suspicious events, the case is assessed as requiring further investigation.

**Triage Priority:** High (proposed, subject to organizational criteria).

**Recommendation:** Escalate to SOC Tier 2 for endpoint telemetry review, process execution verification, persistence assessment, and correlation of the identified external network connections.

## 2. Investigation Objective

The objective of this investigation was to examine an offline packet capture for suspicious network activity and determine whether the available evidence warranted further security investigation or escalation.

The analysis focused on:

- Identifying the primary internal host and relevant external communication endpoints.
- Reviewing network protocols and communication patterns.
- Investigating suspicious HTTP requests and transferred content.
- Identifying script-related delivery activity and executable-format transfers.
- Examining repeated network requests and encrypted connections.
- Correlating significant events into an evidence-supported activity timeline.
- Documenting investigation indicators and relevant artifacts.
- Distinguishing confirmed network observations from unverified endpoint actions.
- Determining an appropriate SOC Tier 1 escalation recommendation.

The investigation was limited to the evidence available from the packet capture and did not include endpoint forensic analysis or malware execution.

## 3. Dataset Description

### 3.1 Data Source

The investigation was conducted using an offline network packet capture obtained from Malware Traffic Analysis.

Source: [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)

Dataset: 2025-01-22-traffic-analysis-exercise.pcap

The dataset was used as the primary evidence source for identifying suspicious network behavior and reconstructing relevant events.

### 3.2 Capture Characteristics

| Attribute | Value |
| --- | --- |
| File format | PCAP |
| Approximate file size | 26 MB |
| Total captured packets | 39,427 |
| IPv4 packets | 39,087 |
| ARP packets | 340 |
| Capture start date | January 22, 2025 |
| Capture end date | January 23, 2025 |
| Capture duration | Approximately 53 minutes and 22 seconds |
| Primary internal host | 10.1.17.215 |

The capture contains multiple network protocols, including TCP, UDP, DNS, HTTP, TLS, ARP, and Windows-related network services.

The analysis was limited to traffic present within the recorded capture interval.

Timestamp interpretation was based primarily on relative time values displayed by Wireshark. The capture's original timezone was not independently verified.

## 4. Analysis Environment

### 4.1 Primary Investigation Environment

The packet capture was analyzed using Wireshark in an isolated Windows 11 virtual machine.

The primary analysis was conducted offline to reduce unnecessary interaction with external systems and potentially suspicious transferred content.

### 4.2 Tools and Features

| Tool or Feature | Investigation Purpose |
| --- | --- |
| Wireshark | Primary packet-level traffic analysis |
| Protocol Hierarchy | Protocol distribution assessment |
| IPv4 Endpoints | Identification of active network hosts |
| IPv4/TCP Conversations | Examination of communication patterns |
| Display Filters | Targeted protocol and traffic investigation |
| Follow TCP Stream | Inspection of TCP application data |
| HTTP Packet Details | Request, response, and transferred content analysis |
| DNS Analysis | Investigation of DNS queries and responses |
| TLS Metadata Analysis | Examination of encrypted session characteristics |
| Python / Scapy | Optional automated traffic extraction and CSV generation |

The primary investigation findings were established through Wireshark analysis.

A Python-based helper tool was also developed as an optional, reusable component. Its revised general-purpose version was not used as the authoritative source for incident conclusions.

## 5. Investigation Methodology

### 5.1 Initial Network Triage

The investigation began with an assessment of the packet capture's general characteristics.

This included:

- Reviewing capture metadata and duration.
- Examining the Protocol Hierarchy.
- Identifying active IPv4 endpoints.
- Reviewing IPv4 and TCP conversations.
- Identifying significant internal-to-external communication patterns.

The initial triage identified 10.1.17.215 as the primary internal host for further investigation.

### 5.2 Protocol-Level Analysis

Targeted analysis was performed across relevant network protocols.

**DNS Analysis**

DNS requests and responses were reviewed to identify queried domains, resolution behavior, and potentially unusual patterns.

**HTTP Analysis**

HTTP requests and responses were examined to identify transferred resources, response codes, request paths, and suspicious application content.

**TCP Analysis**

TCP conversations, stream characteristics, retransmissions, and connection termination events were examined to establish communication context.

**TLS Analysis**

TLS handshake metadata, connection characteristics, and available certificate information were reviewed without decrypting application data.

### 5.3 Suspicious Content Inspection

Relevant HTTP responses were inspected through Wireshark.

The investigation identified:

- VBScript-like component content.
- Obfuscated PowerShell-related content.
- HTTP transfers containing Windows PE-format characteristics.

Transferred content was reviewed without intentionally executing suspicious scripts or binaries.

### 5.4 Evidence Correlation

Related network events were correlated using:

- Source and destination IP addresses.
- TCP stream identifiers.
- HTTP request and response relationships.
- HTTP resource paths.
- Frame numbers.
- Relative timestamps.
- Observed transferred content.

This process supported the reconstruction of a suspected multi-stage sequence of network activity.

### 5.5 IOC and Behavioral Assessment

Relevant IP addresses, HTTP paths, domain names, and file-related artifacts were documented.

Indicators were classified according to the available evidence.

Observed network artifacts were not automatically classified as confirmed malicious IOCs.

Repeated HTTP requests, startup-related reporting, and encrypted communications were evaluated as possible behavioral indicators rather than definitive proof of command-and-control or persistence.

### 5.6 Timeline Reconstruction

Significant network events were organized chronologically using Wireshark frame numbers and relative timestamps.

Directly observed events were distinguished from inferred relationships and unverified endpoint actions.

### 5.7 Findings Validation and Escalation

Each major finding was evaluated against its supporting evidence.

Confidence was assigned according to the directness and consistency of the available observations.

The investigation concluded with a SOC Tier 1 assessment of potential impact, limitations, and the need for escalation.

### 5.8 Investigation Boundaries

The investigation was limited to passive analysis of the available network capture.

It did not include:

- Malware execution or dynamic malware analysis.
- Endpoint process or EDR telemetry.
- Verification of local file execution.
- Windows Startup folder inspection.
- TLS application-data decryption.
- Confirmation of the original initial access vector.
- Definitive malware family or threat actor attribution.

These limitations were considered when interpreting the findings and preparing the escalation recommendation.

## 6. Methodology Summary

The investigation followed a structured, evidence-based workflow progressing from general network triage to focused protocol analysis, suspicious content inspection, evidence correlation, and final incident assessment.

This approach provided a reproducible basis for documenting suspicious network behavior while preserving the distinction between confirmed observations and unverified security hypotheses.

## 7. Technical Findings

### 7.1 Investigation Overview

The investigation identified five primary findings associated with suspicious network activity involving the internal host DESKTOP-L8C5GSJ (10.1.17.215).

The findings were established through packet-level inspection, HTTP request and response analysis, TCP stream examination, TLS metadata inspection, and correlation of previously documented evidence.

The following findings distinguish verified network observations from suspected endpoint actions.

### 7.2 Finding F-001 — Suspicious Script Delivery

**Confidence:** High for observed script delivery and embedded download references.

**Primary Internal Host:** 10.1.17.215

**External Server:** 5.252.153.241:80

**Evidence**

| Frame | Observation |
| --- | --- |
| 5031 | HTTP GET /api/file/get-file/264872 |
| 5033 | HTTP 200 response containing 417 bytes of VBScript-like content |
| 5063 | HTTP GET /api/file/get-file/29842.ps1 |
| 5071 | HTTP 200 response containing 1,512 bytes of obfuscated PowerShell |
| 13671 | HTTP GET /api/file/get-file/pas.ps1 |
| 13675 | HTTP 200 response containing 1,553 bytes of additional obfuscated PowerShell |

**Technical Analysis**

The initial HTTP response contained an XML-like component structure with embedded VBScript.

The observed content included references to:

- CreateObject("Wscript.Shell")
- objShell.Run
- PowerShell execution
- Hidden-window execution options
- System.Net.WebClient
- DownloadString

The embedded download URL referenced:

`http://5.252.153.241:80/api/file/get-file/29842.ps1`

A subsequent HTTP request for this resource was observed in frame 5063, followed by a successful response in frame 5071.

The PowerShell-related response contained obfuscation indicators, including dynamic execution and encoded or transformed string operations.

A second obfuscated PowerShell response was observed later in the capture.

**Security Significance**

The combination of Windows scripting content, embedded PowerShell download functionality, obfuscation, and corresponding HTTP transfers is consistent with suspicious multi-stage script delivery.

The embedded URL provides direct code-level correlation between the initial component and a subsequent network request.

**Limitations**

The PCAP confirms transfer of the relevant content but does not independently prove that the VBScript or PowerShell instructions were executed on the endpoint.

The original initial access vector remains unknown.

Assessment: Suspicious multi-stage script delivery identified.

### 7.3 Finding F-002 — Periodic HTTP Polling

**Confidence:** High for the observed repeated HTTP request pattern; command-and-control functionality unconfirmed.

**Internal Host:** 10.1.17.215

**External Server:** 5.252.153.241:80

**Evidence**

The internal host repeatedly requested the following HTTP resource:

`/1517096937`

A previously applied Wireshark filter identified 584 matching GET requests originating from the internal host.

The reviewed request sample demonstrated intervals of approximately 5.19 seconds.

**Technical Analysis**

Repeated HTTP requests to the same external resource can indicate automated application behavior.

In this case, the polling activity occurred alongside other suspicious communications involving the same external server.

The combination of repeated requests and related script delivery increases the significance of the observed traffic.

**Security Significance**

The pattern is consistent with possible automated status checking, polling, or command-and-control-related communication.

However, periodic HTTP activity alone is not sufficient to establish malicious beaconing or confirmed C2 functionality.

**Limitations**

- The approximate interval was established from a reviewed sample, not every request.
- No definitive command exchange was demonstrated.
- The responsible endpoint process was not identified.
- Alternative automated application behavior has not been excluded.

Assessment: Suspicious periodic HTTP activity requiring correlation.

### 7.4 Finding F-003 — PE-Format File Transfers

**Confidence:** High for network delivery and observed executable-format characteristics.

**Internal Host:** 10.1.17.215

**External Server:** 5.252.153.241:80

**Evidence**

| Request Frame | Response Frame | Resource | Response Size |
| --- | --- | --- | --- |
| 8002 | 12888 | /api/file/get-file/TeamViewer | 4,380,968 bytes |
| 12890 | 13641 | /api/file/get-file/Teamviewer_Resource_fr | 668,968 bytes |

Both resources were transferred through HTTP.

**Technical Analysis**

The HTTP responses contained binary content beginning with the MZ signature and additional characteristics consistent with Windows Portable Executable files.

The first object included the recognizable DOS stub text commonly associated with PE executables.

The resource names contained TeamViewer-related strings, but the names alone do not establish that the files were authentic TeamViewer software.

**Security Significance**

The transfer of executable-format objects from the same server involved in suspicious script delivery raises additional concerns about possible payload staging or software deployment.

The relationship between the transferred objects and the earlier scripting activity remains under investigation.

**Limitations**

- The identity and authenticity of the files were not independently verified.
- The files were not executed during the investigation.
- No endpoint evidence confirmed local execution or installation.
- Malware classification was not established.

Assessment: Suspicious executable-format transfers observed.

### 7.5 Finding F-004 — Possible Persistence Reporting

**Confidence:** High for the observed HTTP message; actual persistence not established.

**Internal Host:** 10.1.17.215

**External Server:** 5.252.153.241:80

**Evidence**

| Frame | Observation |
| --- | --- |
| 13677 | HTTP GET containing a startup-related status message |
| 13687 | HTTP 404 response to the corresponding request |

The HTTP request contained URL-encoded text representing:

message = startup shortcut created; status = success;

**Technical Analysis**

The request appears to report successful creation of a startup shortcut.

Windows Startup shortcuts can be used by legitimate software or as a persistence mechanism by malicious programs.

The message occurred after several script-related and executable-format transfers in the reconstructed event sequence.

**Security Significance**

The reported startup shortcut operation is relevant to the hypothesis of possible persistence activity.

The message provides a reason to investigate Windows Startup folder modifications and associated process execution events.

**Limitations**

- No endpoint telemetry verified creation of the shortcut.
- The shortcut target, filename, and location were not established.
- The reporting program was not identified.
- The HTTP message cannot independently prove successful persistence.

Assessment: Possible persistence-related status reporting observed; endpoint persistence unverified.

### 7.6 Finding F-005 — Unidentified Encrypted TLS Communications

**Confidence:** High for observed encrypted communications; Low for the command-and-control hypothesis.

**Internal Host:** 10.1.17.215

External Endpoint: 45.125.66.32:2917

**Evidence**

| Frame | Observation |
| --- | --- |
| 19302 | TCP SYN initiating a connection to port 2917 |
| 19303 | TCP SYN-ACK |
| 19304 | TCP ACK |
| 19305 | TLS Client Hello |
| 19307 | TLS Server Hello and certificate-related handshake data |

**Technical Analysis**

The internal host established TLS 1.2 communications with the external endpoint over TCP port 2917.

The reviewed handshake exposed the following characteristics:

- TLS 1.2 session negotiation.
- SNI value containing 45.125.66.32.
- Cipher suite TLS_RSA_WITH_AES_128_GCM_SHA256.
- A certificate containing self-signed indicators.
- Subsequent encrypted application data.

Multiple connections and notable traffic volume were observed involving this external endpoint.

**Security Significance**

The encrypted communications represent an additional network activity of interest, especially given the other suspicious events identified in the capture.

The unusual destination port and certificate characteristics warrant further investigation, but they do not independently establish malicious behavior.

**Limitations**

- TLS application data was not decrypted.
- The communicating application was not identified.
- No command-and-control messages were demonstrated.
- No verified causal relationship to the earlier HTTP transfers was established.
- Data exfiltration was not confirmed.

Assessment: Additional encrypted communications requiring endpoint-level correlation.

### 7.7 Technical Findings Summary

| Finding | Description | Evidence Confidence | Security Assessment |
| --- | --- | --- | --- |
| F-001 | Script-based HTTP delivery | High | Suspicious |
| F-002 | Repeated HTTP polling | High | Possible automated or C2-related behavior |
| F-003 | Executable-format HTTP transfers | High | Suspicious in context |
| F-004 | Startup-related status message | High for observation | Possible persistence reporting |
| F-005 | TLS traffic on TCP/2917 | High for traffic observation | Purpose unknown |

### 7.8 Overall Technical Assessment

The findings support a suspected sequence of potentially coordinated network activity involving script-based delivery, executable-format transfers, repeated HTTP requests, and possible persistence reporting.

The strongest direct correlation was identified between the initial VBScript-like component and the subsequent HTTP request for 29842.ps1.

The additional TLS communications represent a separate investigation artifact whose relationship to the earlier HTTP activity remains unconfirmed.

Taken together, the observations justify escalation for endpoint-level investigation.

The evidence does not establish confirmed malware execution, successful persistence, command-and-control functionality, data exfiltration, or definitive endpoint compromise.

## 8. Indicators of Compromise and Investigation Artifacts

### 8.1 Overview

The investigation identified network addresses, HTTP resources, domain names, and file-related artifacts relevant to the suspicious activity observed in the packet capture.

Indicators are classified according to the available evidence.

An observed artifact or suspicious indicator should not be treated as a confirmed malicious IOC without sufficient validation.

### 8.2 Network Indicators

| Indicator | Type | Classification | Supporting Evidence |
| --- | --- | --- | --- |
| 5.252.153.241 | IPv4 | Suspicious Indicator | Script delivery, PE-format transfers, repeated HTTP requests |
| 45.125.66.32 | IPv4 | Investigation Artifact | TLS 1.2 communications over TCP/2917 |
| 10.1.17.215 | Internal IPv4 | Primary Host Identifier | Internal endpoint involved in the investigated communications |
| ping3.dyngate.com | Domain | Investigation Artifact | Repeated DNS queries returning NXDOMAIN |

The primary suspicious external endpoint is 5.252.153.241, based on the combined HTTP evidence.

The purpose of communications involving 45.125.66.32 remains unknown.

### 8.3 HTTP Resource Indicators

The following HTTP resources were observed in communications involving 5.252.153.241.

| HTTP Resource Path | Significance | Evidence |
| --- | --- | --- |
| /api/file/get-file/264872 | VBScript-like component delivery | 5031, 5033 |
| /api/file/get-file/29842.ps1 | Obfuscated PowerShell delivery | 5063, 5071 |
| /api/file/get-file/pas.ps1 | Additional obfuscated PowerShell delivery | 13671, 13675 |
| /api/file/get-file/TeamViewer | PE-like content transfer | 8002, 12888 |
| /api/file/get-file/Teamviewer_Resource_fr | PE-format content transfer | 12890, 13641 |
| /1517096937 | Repeated HTTP requests | 5073 and subsequent requests |
| /1517096937?k=message... | Startup-related status reporting | 13677, 13687 |

The resource path /1517096937 was associated with 584 matching HTTP GET requests from the internal host.

The full startup-related request contained URL-encoded text reporting successful creation of a startup shortcut.

### 8.4 File and Script Artifacts

| HTTP Resource | Response Frame | HTTP Body Size | Observed Characteristics |
| --- | --- | --- | --- |
| 264872 | 5033 | 417 bytes | VBScript-like component |
| 29842.ps1 | 5071 | 1,512 bytes | Obfuscated PowerShell |
| TeamViewer | 12888 | 4,380,968 bytes | Windows PE-like content |
| Teamviewer_Resource_fr | 13641 | 668,968 bytes | Windows PE-format characteristics |
| pas.ps1 | 13675 | 1,553 bytes | Obfuscated PowerShell |

These identifiers represent HTTP resource names. They were not independently verified as filenames written to the endpoint.

File authenticity, malware classification, and execution status remain unconfirmed.

### 8.5 Hunting and Correlation Guidance

For further investigation, the documented indicators may be used to search relevant security telemetry, including:

- Proxy and firewall logs for communications with 5.252.153.241.
- HTTP request logs for the documented resource paths.
- EDR process and connection telemetry involving 45.125.66.32:2917.
- Endpoint execution records for PowerShell and Windows Script Host activity.
- Windows Startup folder modification records.
- DNS logs for ping3.dyngate.com.

No file hashes or independently verified malware attribution were established during this investigation.

## 9. Event Timeline Reconstruction

### 9.1 Timeline Methodology

Significant events were reconstructed using Wireshark frame numbers and timestamps relative to the beginning of the capture.

The timeline focuses on selected events relevant to the investigated activity rather than every packet recorded in the PCAP.

All times in the following table are relative capture times expressed in seconds.

### 9.2 Reconstructed Event Timeline

| Relative Time (s) | Frame | Event | Evidence |
| --- | --- | --- | --- |
| 60.297799 | 5031 | HTTP GET for /api/file/get-file/264872 | Observed |
| 60.464642 | 5033 | HTTP 200 containing VBScript-like content | Confirmed |
| 62.145732 | 5063 | HTTP GET for /api/file/get-file/29842.ps1 | Observed |
| 62.309349 | 5071 | HTTP 200 containing obfuscated PowerShell | Confirmed |
| 62.366091 | 5073 | HTTP GET for /1517096937 | Observed |
| 124.998139 | 8002 | HTTP GET for /api/file/get-file/TeamViewer | Observed |
| 128.456092 | 12888 | HTTP 200 containing PE-like content | Confirmed |
| 128.458764 | 12890 | HTTP GET for /api/file/get-file/Teamviewer_Resource_fr | Observed |
| 128.827248 | 13641 | HTTP 200 containing PE-format content | Confirmed |
| 128.984576 | 13671 | HTTP GET for /api/file/get-file/pas.ps1 | Observed |
| 129.149454 | 13675 | HTTP 200 containing additional obfuscated PowerShell | Confirmed |
| Before 129.423047 | 13677 | HTTP GET containing startup shortcut status message | Observed |
| 129.423047 | 13687 | HTTP 404 response to startup status request | Confirmed |
| 889.561525 | 19302 | TCP SYN to 45.125.66.32:2917 | Confirmed |

The exact relative timestamp for frame 13677 was not independently recorded in the reviewed evidence.

### 9.3 Phase-Based Interpretation

#### Phase 1 — Initial Script-Related Delivery

The host requested a VBScript-like component containing an embedded PowerShell download command.

A subsequent HTTP request referenced the same PowerShell resource identified within the component.

This provides direct code-level correlation between the two events.

#### Phase 2 — Repeated HTTP Activity

Repeated requests to /1517096937 were observed.

The reviewed sample demonstrated approximately five-second intervals.

Automated or command-and-control-related behavior remains a hypothesis rather than a confirmed conclusion.

#### Phase 3 — Additional File Transfers

Two PE-format or PE-like objects were delivered over HTTP, followed by another obfuscated PowerShell response.

The network evidence confirms delivery, not endpoint execution.

#### Phase 4 — Possible Persistence Reporting

An HTTP request included a status message indicating successful creation of a startup shortcut.

No endpoint telemetry was available to confirm the reported operation.

#### Phase 5 — Additional Encrypted Communication

A later TCP connection to 45.125.66.32:2917 was observed.

TLS metadata was examined, but the application purpose and relationship to earlier HTTP events remain unknown.

### 9.4 Timeline Assessment

The reconstructed timeline is consistent with a suspected multi-stage sequence of suspicious network activity.

The strongest direct correlation involves the embedded PowerShell download URL and the corresponding subsequent HTTP request.

Other relationships are based on temporal proximity and supporting network context.

The timeline does not independently establish successful malware execution, persistence, command-and-control activity, or endpoint compromise.

### 9.5 Timeline Limitations

The timeline represents events observed within the available capture interval.

Activities outside the capture window may not be represented.

Relative timestamps were used because the capture's original timezone was not independently verified.

Chronological order alone should not be interpreted as proof of causality.

## 10. Potential Impact Assessment

### 10.1 Overview

The investigation identified suspicious network activity involving script delivery, executable-format transfers, periodic HTTP requests, and possible persistence-related reporting.

The available evidence raises concerns about potential unauthorized code execution and persistence.

However, the actual security impact on the internal host has not been independently established.

The following assessment distinguishes potential consequences from confirmed outcomes.

### 10.2 Potential Security Impact

| Potential Impact | Related Finding | Assessment |
| --- | --- | --- |
| Unauthorized code execution | F-001 | Possible; not verified |
| Unauthorized executable execution | F-003 | Possible; not verified |
| Persistence | F-004 | Possible; not verified |
| Command-and-control activity | F-002, F-005 | Suspected; not confirmed |
| Data exfiltration | No direct supporting evidence | Not established |
| Lateral movement | No supporting evidence identified | Not established |

### 10.3 Primary Security Concerns

The most significant concerns involve possible unauthorized code execution, executable deployment, and persistence.

These concerns are supported by the combined observations of:

- HTTP delivery of VBScript-like content containing a PowerShell download command.
- Subsequent obfuscated PowerShell-related responses.
- Transfers of two PE-format or PE-like objects.
- A startup shortcut success message.
- Repeated HTTP communications with the same external server.

The combined activity is consistent with a potentially coordinated, multi-stage sequence.

Nevertheless, network delivery does not independently establish endpoint execution or successful compromise.

### 10.4 Confirmed Impact

No specific endpoint compromise, persistence mechanism, data loss, or operational disruption was independently confirmed.

The actual impact remains undetermined pending endpoint-level investigation.

## 11. Recommendations

### 11.1 Escalation to SOC Tier 2

**Escalation Decision:** Recommended

**Proposed Priority:** High

The combination of suspicious script delivery, executable-format transfers, periodic HTTP requests, and startup-related reporting warrants further investigation.

The proposed priority should be reviewed according to the organization's incident severity criteria and asset criticality.

### 11.2 Endpoint Execution Verification

Review endpoint security telemetry for evidence of Windows Script Host and PowerShell execution associated with the investigated activity.

Where available, examine:

- EDR process execution records.
- Parent-child process relationships.
- PowerShell operational and script logging.
- Relevant Windows Security events.

Related Finding: F-001

### 11.3 File and Payload Verification

Determine whether the transferred executable-format objects were written to disk or executed.

Validate suspicious files through approved security procedures, including file hash analysis, signature inspection, and authorized malware triage.

Related Finding: F-003

### 11.4 Persistence Verification

Inspect Windows Startup folder modifications and shortcut-related file activity.

Determine whether a startup shortcut was created and identify the executable or script targeted by any relevant shortcut.

Related Finding: F-004

### 11.5 Network-to-Process Correlation

Correlate the documented network connections with endpoint processes and available firewall, proxy, or EDR telemetry.

Prioritize investigation of:

- 5.252.153.241:80
- 45.125.66.32:2917
- Repeated requests to /1517096937

Determine whether these connections are associated with authorized applications, automated software activity, or potentially malicious behavior.

Related Findings: F-002 and F-005

### 11.6 Scope and Containment Assessment

Determine whether other endpoints communicated with the identified external infrastructure.

If malicious activity is confirmed or an immediate risk is established, evaluate containment measures according to the organization's incident response procedures.

Potential actions may include endpoint isolation or network restrictions, subject to authorization and operational impact assessment.

## 12. Investigation Limitations

### 12.1 Network-Only Evidence

The investigation was based primarily on an offline packet capture.

The analysis provided visibility into recorded network communications but did not provide direct access to endpoint process execution, local file-system activity, or EDR telemetry.

### 12.2 Unverified Endpoint Actions

The following actions could not be independently verified:

- Execution of the transferred VBScript-like content.
- Execution of the obfuscated PowerShell scripts.
- Installation or execution of the transferred PE-format objects.
- Creation of the reported startup shortcut.
- Establishment of a persistent access mechanism.

### 12.3 Command-and-Control Uncertainty

Repeated HTTP requests and encrypted TLS communications were observed.

However, the available evidence does not establish that either communication channel was used for command-and-control operations.

The responsible processes and application-layer purpose of the encrypted traffic remain unknown.

### 12.4 Data Exfiltration

No confirmed data exfiltration was established.

Encrypted traffic and high packet volume do not independently prove that sensitive information was transferred.

### 12.5 Initial Access

The original intrusion vector was not identified.

The earliest suspicious script-related HTTP response in the reviewed sequence should not be interpreted as the confirmed initial entry point.

### 12.6 Capture Scope and Timestamp Limitations

The packet capture represents a limited observation interval.

Activities occurring outside that interval may not be visible.

The capture's original timezone was not independently verified; relative timestamps were therefore used for event reconstruction.

### 12.7 Malware Attribution

The transferred content was not conclusively attributed to a malware family or threat actor.

Resource names containing TeamViewer-related strings do not independently establish file authenticity or maliciousness.

### 12.8 Overall Limitation Assessment

The available evidence is sufficient to support a recommendation for further investigation.

It is not sufficient to establish confirmed malware execution, successful persistence, definitive command-and-control functionality, data exfiltration, or endpoint compromise.

## 13. SOC Tier 1 Final Assessment

The investigation identified suspicious network activity involving the internal host DESKTOP-L8C5GSJ (10.1.17.215).

The primary observations included:

- Script-based HTTP delivery.
- Obfuscated PowerShell-related content.
- Executable-format file transfers.
- Repeated HTTP requests.
- Startup-related status reporting.
- Additional encrypted TLS communications.

The evidence supports a suspected multi-stage security incident requiring endpoint-level validation.

The strongest direct correlation involves a VBScript-like component containing a PowerShell download URL and a subsequent HTTP request for that same resource.

Other suspected relationships remain subject to further investigation.

**Final SOC Tier 1 Recommendation:** Escalate to SOC Tier 2.

Proposed Triage Priority: High.

**Confirmed Endpoint Compromise:** Not established.

The case should remain open pending additional endpoint evidence and further assessment by the appropriate security response team.

## 14. Conclusion

The investigation demonstrated a structured approach to identifying, analyzing, correlating, and documenting suspicious network activity using Wireshark.

The findings support escalation based on multiple related network observations, while acknowledging important limitations inherent in packet-capture-only analysis.

The final assessment avoids treating suspicious activity as confirmed malware execution or endpoint compromise without additional supporting evidence.

Further investigation is recommended to determine the responsible processes, verify reported endpoint actions, and establish the actual security impact.


---

## Evidence and Publication Notes

- **Primary evidence:** The original offline PCAP and the analyst's Wireshark observations, documented in the private investigation notebook.
- **Screenshot references:** Evidence images are selected and named during repository preparation (Step 6.2). No screenshot links are asserted here until their final paths have been verified.
- **Optional automation:** A reusable Scapy helper script is maintained separately. Its revised version has not yet been independently validated against this PCAP; it is **not** a source for the incident conclusions above.
- **Safe publication:** Do not publish the raw PCAP, extracted script or executable payloads, private environment details, or unreviewed binary artifacts.
- **Assessment boundary:** No endpoint telemetry was obtained. Script execution, persistence, C2 functionality, and compromise are not confirmed.
