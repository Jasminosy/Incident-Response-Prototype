import '../src/style.css';

// ---------- 1) Measures Definitions ----------
const investigativeMeasures: Record<string, string> = {
  'IM001': 'interview affected user(s)',
  'IM003': 'Verify if artifact is malicious (Threat DBs, Threat Analyzer, Sandbox Solutions)',
  'IM004': 'ask if the connection is expected',
  'IM005': 'ask if the scans are expected',
  'IM007': 'Scan shared drives and file servers for identical malicious files or ransomware-encrypted patterns (hash, filename, extension).',
  'IM008': 'export relevant log excerpts for the exact timeframe (firewall, proxy, EDR, app)',
  'IM011': 'review DNS queries for malicious domains or beaconing',
  'IM012': 'verify in proxy and EDR logs if suspicious artifact(s) were accessed or executed', //WICHTIG
  'IM013': 'enumerate recent config changes (services, policies, cron/Task Scheduler)',
  'IM014': 'review firewall/proxy logs for suspicious IPs and unusual outbound connections',
  'IM016': 'investigate timeline before clearing',
  'IM017': 'locate suspicious artifact(s) on affected host(s) using EDR, AV logs or file search (identify path and hash)',
  'IM021': 'correlate logs in SIEM/XDR for auth, process, and network anomalies',
  'IM022': 'Check login activity for anomalies (successful/failed logins, RDP, domain logs)', //WICHTIG
  'IM029': 'Extract Indicators of Compromise (hashes, IPs, domains, filenames)',
  'IM030': 'build a timeline of events to reconstruct the attack (logs, file metadata, timestamps)',
  'IM032': 'analyze NetFlow/PCAP/Zeek for C2, exfiltration, or lateral movement', //WICHTIG
  'IM033': 'hunt for additional infected endpoints in EDR/XDR (processes, detections, hashes)',
  'IM034': 'analyze process tree and parent-child relations',
  'IM035': 'check system for new user accounts',
  'IM036': 'review scheduled tasks and startup folders manually',
  'IM038': 'collect and analyze email',
  'IM039': 'correlate indicators with Threat Intelligence Feeds',
  'IM040': 'review cloud audit logs (Azure AD, AWS CloudTrail, M365)',
  'IM041': 'verify backup integrity and timestamp',
};
const basicForensicMeasures: Record<string, string> = {
  'BFM001': 'take a forensic image of the affected system(s)', //nur durch Logik ins Mapping
  'BFM016': 'Capture transient evidence (screenshots, visible messages, logged-on users, quick ps/netstat).',
  'BFM017': 'Check COM objects and common registry keys for suspicious entries.',
  'BFM019': 'Collect volatile host context (running processes, open ports, logged-in sessions) WITHOUT full RAM dump.', 
  'BFM020': 'Capture running services and scheduled tasks (services, Task Scheduler, cron).',
  'BFM026': 'Inspect Prefetch to identify recently executed programs.',
  'BFM009': 'Preserve network evidence for the time window (pcap/flow export, span capture, Zeek slice).',
  'BFM024': 'Review browser artefacts for phishing/download traces (history, cache, downloads).',
  'BFM025': 'Identify unknown executables in autoruns/startup/scheduled tasks (autoruns, binaries).',
  'BFM027': 'Check hosts file and DNS cache for malicious domains or IPs.',
  'BFM028': 'List persistence mechanisms to detect automatic malware execution (run keys, services).',
  'BFM037': 'Verify integrity of system binaries (sigcheck, hashes).'
};

const professionalForensicMeasures: Record<string, string> = {
  'PFM019': 'Acquire FULL memory dump and preserve it for analysis.',
  'PFM023': 'Analyze Windows Jump Lists for recently opened files/tools.',
  'PFM031': 'Analyze NTFS Master File Table (MFT) for file system artefacts.',
  'PFM042': 'Map and analyze AD lateral movement paths (e.g., BloodHound, GPO/object changes).',
  'PFM043': 'Deep analysis of registry run-once/run-always keys and persistence.',
  'PFM044': 'Analyze memory for injected code and artefacts (e.g., Volatility/Rekall).',
  'PFM045': 'Preserve evidence chain (write-blockers, hashing, chain-of-custody documentation).',
  'PFM006': 'Secure forensic evidence for legal proceedings (forensic readiness, chain-of-custody).',
  'PFM010': 'Perform memory dump analysis (post-acquisition, forensic tooling).'
};
const measures: Record<string, string> = {
    'M001': 'isolate compromised client(s)/server(s)', //WICHTIG
    'M002': 'isolate compromised network (VLAN, location)', //WICHTIG
    'M003': 'deactivate compromised account(s)', //WICHTIG
    'M004': 'reset compromised user password(s)',
    'M005': 'reimage client(s)',
    'M006': 'block sender domain(s) or quarantine similar email(s) organization-wide',
    'M007': 'block or quarantine malicious file(s) identified by known malicious hash(es) organization-wide',
    'M008': 'block malicious url(s)',
    'M009': 'Engage external Incident Response support', //nur durch Logik ins Mapping
    'M010': 'run full AV-scan',
    'M011': 'quick scan for similar behavior in other cases',
    'M012': 'quarantine / delete affected emails organization-wide',
    'M013': 'disable task(s)',
    'M014': 'identify malicious process(es)',
    'M015': 'stop malicious process(es)',
    'M016': 'block specific suspicious IP addresses at host or firewall level',
    'M017': 'identify the content of data that may have been leaked', //WICHTIG
    'M018': 'clear/revoke user session(s)',
    'M019': 'block malicious domain(s)',
    'M020': 'Replace compromised component with verified clean version', //nur durch Logik ins Mapping
    'M021': 'increase logging level',
    'M022': 'backup critical data', //teiweise durch Logik
    'M023': 'disconnect external devices',
    'M024': 'Identify additional compromised hosts and user accounts based on the following investigation results and indicators. Containment has to be done for other findings', // nur durch Logik ins Mapping
    'M025': 'remove persistence mechanisms',
    'M026': 'revoke access tokens/API keys',
    'M027': 'block suspicious processes via EDR',
    'M028': 'reset MFA / revoke trusted devices',
    'M029': 'safely collect suspect artifact(s) locally (copy and extract hash)',
    'M030': 'Inform the company Data Protection Officer -> EU-GDPR duty to report within 72h deadline', //nur durch Logik ins Mapping
    'M031': 'Document the incident in as much detail as possible -> Compliance requirement', //nur durch Logik ins Mapping
    'M032': 'Document the incident -> Compliance requirement', //nur durch Logik ins Mapping
    'M033': 'Inform the company Information Security Officer -> ISO27001 duty to report internally', //nur durch Logik ins Mapping
    'M034': 'Inform the company Information Security Officer and Data Protection Officer -> NIS-2 duty to set up a Early Warning within 24h deadline. Incident Notification within 72h deadline. Final Report within 30 days.', //nur durch Logik ins Mapping
    'M035': 'Inform the company Information Security Officer -> BSIG & German IT Security Act 2.0 duty to report immediately', //nur durch Logik ins Mapping
    'M036': 'Inform the company Information Security Officer -> DORA duty to report immediately', //nur durch Logik ins Mapping
    'M037': 'revoke or rotate encryption keys / certificates',
    'M039': 'Block Command and Control (C2) communication organization-wide via firewall or proxy policy.',
    'M040': 'force company-wide password reset',
    'M041': 'disable vulnerable interface or port (e.g. RDP, SMB)',
    'M042': 'limit or disable external sharing (cloud, M365, Google Workspace)',
    'M043': 'restore server(s)/VM(s)/DB(s) from clean backup', //nur durch Logik ins Mapping
    'M044': 'post-incident monitoring for reinfection or lateral movement',
    'M045': 'Securely restore compromised user accounts (reset password, revoke sessions, refresh MFA, verify tokens/keys, review permissions before reactivation)',
    'M046': 'Involve your IT Forensics Team -> Forensic compliance requirements are weak', //nur durch Logik ins Mapping
    'M047': 'remove all potential IoC from the host(s)',
    'M048': 'reimage server(s)', //nur durch Logik ins Mapping
    'M050': 'Inform the company Information Security Officer -> TKG duty to report within 24h deadline', //nur durch Logik ins Mapping
    'M051': 'Inform the company Information Security Officer -> BAIT / VAIT / KAIT / ZAIT duty to report within 28h deadline, but within 4h after classification of the criticality.', //nur durch Logik ins Mapping
    'M052': 'Inform the company Information Security Officer -> EnergieKRITIS / EnWG §11 duty to report immediately', //nur durch Logik ins Mapping
    'M053': 'Inform the company Information Security Officer -> SOC 2 duty to report internally', //nur durch Logik ins Mapping
    'M054': 'Inform the company Information Security Officer -> BSI IT-Grundschutz duty to report internally', //nur durch Logik ins Mapping
    'M055': 'Inform the company Information Security Officer -> C5 duty to report internally', //nur durch Logik ins Mapping
    'M056': 'Inform the company Information Security Officer -> TISAX duty to report internally & to report to partners regarding contracts', //nur durch Logik ins Mapping
};
const allMeasures = { ...investigativeMeasures, ...basicForensicMeasures, ...professionalForensicMeasures, ...measures };

// ---------- 2) Taktik-zu-Maßnahmen-Mapping ----------
// Dieses Mapping ordnet MITRE ATT&CK Taktiken (und andere Angriffsmuster) den entsprechenden Incident-Response-Maßnahmen zu.
const tacticToActionMap: Record<string, string[]> = {

'WannaCry': ['M001','M002','IM012','IM017','M029','M007','IM003','IM039','M024','IM033','IM032','BFM020','IM021','IM014','IM011','IM007','M017','IM041','M020','M005'],
'LockBit':  ['M001','M002','IM012','IM017','M029','IM003','M007','IM039','M017','M024','IM033','IM032','IM020','PFM042','IM021','IM014','IM011','IM007','IM022','IM035','IM041','M037','M005'],
'Conti':    ['M001','M002','IM012','IM017','M029','IM003','M007','IM039','M017','M024','IM033','IM032','IM020','PFM042','IM021','IM014','IM011','IM007','IM022','IM041','M022','M005'],
'Solar Winds': ['IM012','M017','M001','M002','IM033','PFM042','IM035','IM032','BFM016','PFM019','PFM044','BFM020','PFM031','IM021','IM040','IM017','M037','M026','M028','M007','M025','M047','M044'],
'SupplyChainCodeSigning': ['IM012','M017','M001','M002','M015','BFM016','PFM019','BFM020','M029','M037','M026','M028','M040','IM029','M007','IM021','IM040','IM033','IM032','M045','M020'],
'SCCleaner': ['IM012','M017','IM017','IM024','IM007','M001','M018','M028','PFM023','BFM026','PFM031','BFM016','PFM019','M007','M008','M006','M012','IM033','IM032','BFM028','BFM025','M025','M015','M005','M044'],
'HOK': ['IM012','M017','M001','M002','M003','M018','M028','M026','BFM016','PFM019','PFM044','BFM020','M029','IM010','IM021','IM033','IM032','IM011','IM022','IM035','M015','M013','BFM027','M007','M016','M025','M047','IM029','IM030','IM041','M005','M044'], 
'DependencyHijack': ['IM012','IM014','IM004','M001','M039','M016','M018','M003','M026','M028','IM017','IM008','IM011','IM021','IM022','IM029','IM039','IM034','IM032','IM033','IM013','IM036','IM035','BFM028','BFM017','BFM037','BFM016','BFM019','BFM009','M025','M027','M020','M045','M044'],
'Mirai': ['IM012','IM014','IM004','M001','M039','M016','M018','M003','M026','M028','M041','IM017','IM032','IM033','IM008','IM021','IM022','IM011','IM029','IM039','IM034','IM013','IM036','IM035','BFM028','BFM017','BFM037','BFM016','BFM019','BFM009','M025','M027','M020','M045','M044'],
'Equifax': ['IM012','IM014','IM004','M001','M039','M016','M018','M003','M026','M028','IM017','IM008','IM011','IM021','IM022','IM029','IM039','IM034','IM032','IM033','IM013','IM036','IM035','BFM028','BFM017','BFM037','BFM016','BFM019','BFM009','M025','M027','M020','M045','M044'],
'Insider Threat': ['IM001','IM022','IM038','IM040','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM020','BFM037','IM016','IM039','M003','M018','M028','M026','M024','M047','M044','M021'],
'XSS': ['IM001','IM038','IM014','IM012','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM024','IM016','IM039','M008','M019','M016','M021','M024','M044'],
'SQLi': ['IM001','IM014','IM012','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM020','BFM037','IM016','IM039','M001','M016','M025','M024','M047','M044','M043','M021'],
'Golden': ['IM001','M003','M018','M028','IM022','BFM016','BFM019','PFM019','PFM010','PFM044','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM028','BFM037','IM016','IM039','M025','M024','M047','M044','M040','M021'],
'E-Mail MitM': ['IM001','IM038','IM014','IM012','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM024','BFM037','IM016','IM039','M019','M008','M016','M024','M047','M044','M021'],
'Skeleton Key Attack': ['IM001','M003','M018','IM022','BFM016','BFM019','PFM019','PFM010','PFM044','IM034','IM017','IM033','IM021','IM029','IM030','IM013','BFM028','BFM037','IM016','IM039','M015','M025','M024','M047','M044','M040','M021'],
'Excel': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM012','IM014','IM033','IM021','IM038','IM029','IM030','IM013','BFM026','BFM025','BFM037','IM016','IM039','M015','M027','M047','M024','M044','M021'],
'Word': ['IM001','M001','BFM016','BFM019','IM038','IM017','IM034','IM012','IM014','IM033','IM021','IM029','IM030','IM013','BFM026','BFM025','BFM037','IM016','IM039','M015','M027','M047','M024','M044','M021'],
'Account enumeration reconnaissance': ['IM001','M001','BFM016','BFM019','IM022','IM014','IM012','IM021','IM029','IM030','IM013','IM032','IM016','IM039','M016','M024','M047','M044','M021'],
'Overpass the hash Attack': ['IM001','M003','M018','M028','IM022','BFM016','BFM019','IM017','IM034','IM033','PFM019','PFM010','PFM044','IM021','IM029','IM030','IM013','BFM028','BFM037','IM016','IM039','M025','M024','M047','M044','M021'],
'Malware Loader': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM012','IM014','IM032','IM021','IM029','IM030','IM013','BFM026','BFM025','BFM037','IM016','IM039','M015','M027','M039','M047','M024','M044','M021'],
'BumbleBee': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM032','IM021','IM012','IM014','IM029','IM030','IM013','BFM026','BFM025','BFM037','PFM019','PFM010','PFM044','IM016','IM039','M015','M027','M039','M024','M047','M044','M021'],
'C2 Server': ['IM004','IM012','IM014','IM017','M001','M039','M016','IM008','IM011','IM021','IM022','IM029','IM039','IM032','IM033','IM034','IM013','IM036','M025','M027','M020','M045','M044'],
'BEC': ['M003','M018','M028','M004','IM022','IM040','IM012','IM008','IM011','IM038','IM014','IM029','IM030','IM021','IM033','IM034','BFM016','BFM024','BFM027','M016','M019','M039','M025','M047','M017','M045','M044','M021'],
'Credential Harvesting': ['IM001','IM022','IM014','IM012','IM038','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM024','IM016','IM039','M003','M018','M028','M026','M024','M047','M044','M021'],
'Drive-by Download': ['IM001','IM014','IM012','IM038','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM024','BFM026','M015','M027','M039','IM016','IM039','M047','M024','M044','M021'],
'Formjacking': ['IM001','IM038','IM014','IM012','IM021','IM029','IM030','BFM024','BFM016','BFM019','IM016','IM039','M008','M019','M016','M025','M024','M047','M044','M021'],
'Watering Hole': ['IM001','IM014','IM012','IM032','IM038','IM021','IM017','IM034','IM033','IM029','IM030','IM013','BFM016','BFM019','BFM024','BFM026','IM016','IM039','M016','M019','M025','M024','M047','M044','M021'],
'Zero Day': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','BFM037','IM012','IM014','IM021','IM029','IM030','IM013','PFM019','PFM010','PFM044','IM016','IM039','M001','M025','M024','M047','M044','M021'],
'Fileless Malware': ['IM001','M001','BFM016','BFM019','PFM019','PFM010','PFM044','IM034','IM033','IM012','IM014','IM021','IM029','IM030','IM013','BFM028','BFM037','IM016','IM039','M027','M015','M024','M047','M044','M021'],
'LOLBins': ['IM001','M001','BFM016','BFM019','IM034','IM033','IM017','IM012','IM014','IM021','IM029','IM030','IM013','BFM026','BFM028','BFM037','IM016','IM039','M027','M015','M024','M047','M044','M021'],
'Webshell': ['IM001','M001','IM014','IM012','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM026','BFM028','BFM037','IM032','IM016','IM039','M025','M001','M016','M024','M047','M044','M021'],
'SSRF': ['IM001','IM014','IM012','IM032','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM016','BFM019','IM016','IM039','M016','M008','M019','M025','M024','M047','M044','M021'],
'XXE': ['IM001','IM014','IM012','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM024','IM016','IM039','M016','M019','M025','M024','M047','M044','M021'],
'Deserialization': ['IM001','IM014','IM012','IM017','IM034','IM033','IM021','IM029','IM030','BFM016','BFM019','BFM026','BFM037','IM016','IM039','M025','M016','M024','M047','M044','M021'],
'SSO/OAuth Abuse': ['IM001','IM022','IM040','M003','M018','M028','IM038','IM014','IM012','IM021','IM029','IM030','IM013','BFM016','BFM019','IM016','IM039','M026','M024','M047','M044','M021'],
'Cloud Misconfig': ['IM001','IM040','IM022','IM014','IM012','IM021','IM029','IM030','IM013','BFM016','BFM019','IM016','IM039','M042','M026','M024','M047','M044','M021'],
'Dependency Confusion': ['IM001','IM014','IM012','IM038','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM024','BFM037','IM016','IM039','M008','M019','M025','M024','M047','M044','M021'],
'SIM Swap': ['IM001','IM022','IM038','IM040','IM021','IM029','IM030','IM013','IM016','IM039','M003','M018','M028','M026','M024','M047','M044','M021'],
'Cryptojacking': ['IM001','M001','IM032','IM017','IM034','IM033','IM014','IM012','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM026','IM016','IM039','M015','M027','M025','M024','M047','M044','M021'],
'Sidechannel': ['IM001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM021','IM029','IM030','IM013','PFM019','PFM010','IM016','IM039','M001','M025','M024','M047','M044','M021'],
'API Abuse': ['IM001','IM014','IM012','IM038','IM040','IM021','IM029','IM030','IM013','BFM016','BFM019','IM016','IM039','M026','M016','M024','M047','M044','M021'],
'Web API Injection': ['IM001','IM014','IM012','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM026','IM016','IM039','M016','M025','M024','M047','M044','M021'],
'Container Escape': ['IM001','M001','IM032','IM014','IM012','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM020','BFM026','BFM037','IM016','IM039','M001','M016','M025','M024','M047','M044','M021'],
'POS Malware': ['IM001','M001','IM017','IM034','IM033','IM032','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM020','BFM026','BFM037','PFM019','PFM010','PFM044','IM016','IM039','M001','M015','M025','M024','M047','M044','M021'],
'ATM Malware': ['IM001','M001','IM017','IM034','IM033','IM032','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM020','BFM026','BFM037','PFM019','PFM010','PFM044','IM016','IM039','M001','M015','M025','M024','M047','M044','M021'],
'RAT': ['IM001','M001','IM017','IM034','IM033','IM032','IM021','IM014','IM012','IM029','IM030','IM013','BFM016','BFM019','BFM026','BFM037','PFM019','PFM010','PFM044','IM016','IM039','M015','M027','M039','M024','M047','M044','M021'],
'Gh0st': ['IM001','M001','IM017','IM034','IM033','IM032','IM021','IM014','IM012','IM029','IM030','IM013','BFM016','BFM019','BFM026','BFM037','PFM019','PFM010','PFM044','IM016','IM039','M015','M027','M039','M024','M047','M044','M021'],
'Remcos': ['IM001','M001','IM017','IM034','IM033','IM032','IM021','IM014','IM012','IM029','IM030','IM013','BFM016','BFM019','BFM026','BFM037','PFM019','PFM010','PFM044','IM016','IM039','M015','M027','M039','M024','M047','M044','M021'],
'Account Takeover': ['IM001','IM022','M003','M018','M028','IM038','IM040','IM014','IM012','IM021','IM029','IM030','IM013','BFM016','BFM019','IM016','IM039','M026','M024','M047','M044','M021'],
'Code Signing Abuse': ['IM001','M001','BFM016','BFM019','BFM037','IM014','IM012','IM021','IM029','IM030','IM013','IM016','IM039','M025','M024','M047','M044','M021'],
'Physical Access': ['IM001','IM038','IM022','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM016','BFM019','BFM020','IM016','IM039','M023','M001','M024','M047','M044','M021'],
'Info Stealer': ['IM001','M001','IM017','IM034','IM033','IM032','IM021','IM014','IM012','IM029','IM030','IM013','BFM016','BFM019','BFM026','BFM024','IM016','IM039','M015','M027','M039','M024','M047','M044','M021'],

'T1001': ['M016','M019','M039','M001','BFM009','BFM016','IM008','IM011','BFM027','IM014','IM012','IM021','IM032','IM029','IM030','IM033','IM034','PFM019','PFM044','BFM024','M047','M017','M021','M044'],
'T1001.001': ['M016','M019','M039','M001','BFM009','BFM016','IM008','IM011','IM014','IM012','IM021','IM032','IM029','IM030','IM033','IM034','BFM027','PFM019','PFM044','M047','M017','M021','M044'],
'T1001.002': ['M019','M016','M039','M001','BFM024','BFM009','IM008','IM012','IM011','IM014','IM021','IM029','IM030','IM033','IM034','BFM027','BFM016','PFM019','PFM044','PFM023','M017','M047','M021','M044'],
'T1001.003': ['M039','M016','M019','M001','BFM009','BFM016','IM032','IM014','IM008','IM011','IM012','IM021','IM029','IM030','IM033','IM034','BFM027','PFM019','PFM044','M017','M047','M021','M044'],

'T1003': ['M001','M018','BFM016','BFM019','BFM020','BFM026','BFM025','BFM028','BFM037','IM017','IM034','IM008','IM021','IM022','IM033','IM032','IM029','IM030','PFM019','PFM010','PFM044','PFM031','PFM042','M014','M015','M027','M007','M010','M024','M003','M004','M040','M037','M041','M047','M044','M021'],
'T1003.001': ['M001','M018','BFM016','BFM019','BFM020','BFM026','BFM025','BFM028','BFM037','IM017','IM034','IM008','IM021','IM033','IM029','IM030','PFM019','PFM010','PFM044','M014','M015','M027','M007','M010','M024','M003','M004','M040','M047','M044','M021'],
'T1003.002': ['M001','M018','BFM016','BFM019','BFM020','BFM026','BFM025','BFM028','BFM037','IM017','IM034','IM008','IM021','IM022','IM035','IM029','IM030','PFM019','PFM010','PFM044','M014','M015','M027','M007','M010','M024','M003','M004','M047','M044','M021'],
'T1003.003': ['M001','M002','M018','BFM016','BFM019','BFM020','BFM026','IM022','IM021','IM032','IM033','IM034','IM008','IM029','IM030','PFM019','PFM010','PFM044','PFM031','PFM042','M003','M004','M040','M037','M041','M024','M007','M010','M047','M044','M021'],
'T1003.004': ['M001','M018','BFM019','BFM020','BFM025','BFM028','BFM037','IM017','IM034','IM022','IM008','IM021','IM029','IM030','PFM019','PFM010','PFM044','M003','M004','M037','M024','M047','M044','M021'],
'T1003.005': ['M001','M018','BFM016','BFM019','BFM026','BFM024','IM017','IM034','IM022','IM021','IM033','IM029','IM030','PFM019','PFM010','PFM044','M003','M004','M040','M010','M007','M024','M047','M044','M021'],
'T1003.006': ['M001','M002','M018','BFM016','BFM019','IM022','IM040','IM021','IM032','IM033','IM034','IM008','IM029','IM030','PFM019','PFM010','PFM044','PFM042','M003','M004','M040','M037','M041','M024','M047','M044','M021'],
'T1003.007': ['M001','M018','BFM016','BFM019','BFM020','BFM026','BFM037','IM017','IM034','IM032','IM021','IM033','IM029','IM030','PFM019','PFM010','PFM044','M014','M015','M027','M007','M010','M024','M003','M004','M047','M044','M021'],
'T1003.008': ['M001','M018','BFM019','BFM026','IM017','IM034','IM022','IM021','IM033','IM029','IM030','PFM019','PFM010','M003','M004','M040','M024','M047','M044','M021'],

'T1011': ['M001','M018','BFM016','BFM019','BFM020','IM017','IM034','IM033','IM021','IM008','IM029','IM030','IM032','BFM026','BFM025','BFM028','M023','M016','M024','M047','M017','M044','M021'],
'T1011.001': ['M001','M018','BFM016','BFM019','BFM020','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM026','BFM025','BFM028','M023','M024','M047','M017','M044','M021'],

'T1016': ['M001','M018','BFM016','BFM019','IM017','IM034','IM008','IM021','IM033','IM029','IM030','BFM026','BFM028','BFM037','M024','M047','M044','M021'],
'T1016.001': ['M001','M018','BFM016','BFM019','IM011','IM014','IM012','IM017','IM034','IM008','IM021','IM029','IM030','IM033','BFM026','BFM028','BFM037','M024','M047','M044','M021'],
'T1016.002': ['M001','M018','BFM016','BFM019','BFM020','IM017','IM034','IM033','IM021','IM029','IM030','BFM026','BFM028','M023','M024','M047','M044','M021'],

'T1020': ['M001','M018','BFM016','BFM019','BFM020','IM017','IM034','IM033','IM021','IM014','IM012','IM008','IM011','IM029','IM030','IM032','BFM026','BFM025','BFM028','BFM037','M016','M019','M024','M047','M017','M044','M021'],
'T1020.001': ['M001','M018','BFM016','BFM019','BFM020','IM017','IM034','IM033','IM021','IM014','IM012','IM008','IM029','IM030','IM032','BFM026','BFM025','BFM028','BFM037','M016','M019','M024','M047','M017','M044','M021'],

'T1021': ['M001','IM022','IM014','IM012','IM011','IM033','IM034','IM032','IM021','IM029','IM030','IM035','IM008','BFM016','BFM019','BFM026','M027','M016','M024','M047','M044','M021'],
'T1021.001': ['M001','IM022','IM014','IM012','IM011','IM021','IM029','IM030','IM035','IM008','BFM016','BFM019','M016','M027','M024','M047','M044','M021'],
'T1021.002': ['M001','IM022','IM014','IM012','IM011','IM017','IM033','IM034','IM032','IM021','IM029','IM030','IM035','IM008','BFM016','BFM019','BFM026','M027','M016','M024','M047','M044','M021'],
'T1021.003': ['M001','IM012','IM033','IM034','IM014','IM032','IM021','IM029','IM030','IM035','IM008','BFM016','BFM019','BFM020','M027','M016','M024','M047','M044','M021'],
'T1021.004': ['M001','IM022','IM014','IM012','IM011','IM033','IM034','IM021','IM029','IM030','IM035','IM008','BFM016','BFM019','M027','M016','M024','M047','M044','M021'],
'T1021.005': ['M001','IM022','IM014','IM012','IM011','IM033','IM034','IM032','IM021','IM029','IM030','IM035','IM008','BFM016','BFM019','BFM026','M027','M016','M024','M047','M044','M021'],
'T1021.006': ['M001','IM022','IM014','IM012','IM011','IM033','IM034','IM032','IM021','IM029','IM030','IM035','IM008','BFM016','BFM019','BFM026','BFM020','M027','M016','M024','M047','M044','M021'],
'T1021.007': ['M003','M018','M028','IM022','IM040','IM012','IM033','IM021','IM029','IM030','IM035','IM008','BFM016','BFM019','M024','M047','M044','M021'],
'T1021.008': ['M001','IM022','IM014','IM012','IM011','IM033','IM034','IM032','IM021','IM029','IM030','IM035','IM008','BFM016','BFM019','BFM026','BFM020','M027','M016','M024','M047','M044','M021'],

'T1027': ['M031','M001','BFM016','BFM019','IM017','IM003','IM012','IM014','IM011','IM033','IM034','IM008','IM029','IM021','M027','M007','M019','M016','M025','M047','M005','M044','M021'],
'T1027.001': ['M031','M001','BFM016','BFM019','IM017','IM003','IM012','BFM037','IM034','IM008','IM029','IM021','M007','M027','M025','M047','M005','M044','M021'],
'T1027.002': ['M031','M001','BFM016','BFM019','IM017','IM003','IM012','IM034','IM033','IM014','IM011','IM008','IM029','IM021','M027','M007','M019','M016','M025','M047','M005','M044','M021'],
'T1027.003': ['M031','M001','BFM016','BFM019','IM017','IM003','IM012','IM014','IM011','IM008','IM029','IM021','M007','M019','M016','M025','M047','M044','M021'],
'T1027.004': ['M031','M001','BFM016','BFM019','IM017','IM003','IM012','IM034','IM033','IM014','IM032','IM008','IM029','IM021','M027','M007','M019','M016','M025','M047','M005','M044','M021'],
'T1027.005': ['M031','M001','BFM016','BFM019','IM013','IM017','IM012','IM033','IM034','IM008','IM029','IM021','M027','M025','M047','M005','M044','M021'],
'T1027.006': ['M031','M001','BFM016','BFM019','IM038','IM017','IM003','IM012','IM014','IM011','IM034','IM033','IM008','IM029','IM021','M027','M007','M019','M016','M025','M047','M005','M044','M021'],
'T1027.007': ['M031','M001','BFM016','BFM019','IM017','IM012','IM013','IM034','IM033','IM029','IM021','M025','M027','M047','M005','M044','M021'],
'T1027.008': ['M031','M001','BFM016','BFM019','IM017','IM003','IM012','BFM037','IM034','IM033','IM008','IM029','IM021','M027','M007','M025','M047','M005','M044','M021'],
'T1027.009': ['M031','M001','BFM016','BFM019','IM038','IM017','IM003','IM012','IM034','IM033','IM014','IM011','IM008','IM029','IM021','M027','M007','M019','M016','M025','M047','M005','M044','M021'],
'T1027.010': ['M031','M001','BFM016','BFM019','IM012','IM034','IM033','IM008','IM029','IM021','M027','M016','M025','M047','M005','M044','M021'],
'T1027.011': ['M031','M001','BFM016','BFM019','IM017','IM012','IM034','IM033','IM008','IM029','IM021','BFM028','BFM025','M027','M025','M047','M005','M044','M021'],
'T1027.012': ['M031','M001','BFM016','BFM019','IM017','IM012','IM034','IM033','IM029','IM008','IM021','M027','M025','M047','M005','M044','M021'],
'T1027.013': ['M031','M001','BFM016','BFM019','IM017','IM003','IM012','IM034','IM033','IM014','IM008','IM029','IM021','M027','M007','M019','M025','M047','M005','M044','M021'],
'T1027.014': ['M031','M001','BFM016','BFM019','IM012','IM034','IM033','IM029','IM008','IM021','M027','M016','M025','M047','M044','M021'],
'T1027.015': ['M031','M001','BFM016','BFM019','IM012','IM034','IM033','IM017','IM029','IM008','IM021','BFM026','M027','M025','M047','M005','M044','M021'],
'T1027.016': ['M031','M001','BFM016','BFM019','IM012','IM034','IM033','IM017','IM029','IM008','IM021','BFM026','BFM037','M027','M025','M047','M005','M044','M021'],
'T1027.017': ['M031','M001','BFM016','BFM019','IM012','IM034','IM033','IM017','IM029','IM008','IM021','BFM026','BFM028','BFM037','M027','M025','M047','M005','M044','M021'],

'T1030': ['M001','M018','IM014','IM012','IM011','IM021','IM033','IM034','IM032','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','M016','M019','M024','M047','M017','M044','M021'],

'T1036': ['M001','M018','IM017','IM034','IM012','IM033','IM021','IM008','IM029','IM030','BFM026','BFM025','BFM028','BFM037','BFM019','BFM020','M024','M047','M044','M021'],
'T1036.001': ['M001','M018','IM017','IM034','IM012','IM033','IM021','IM008','IM029','IM030','BFM037','BFM026','BFM028','BFM025','BFM019','BFM020','M024','M047','M044','M021'],
'T1036.002': ['M001','M018','IM017','IM012','IM034','IM021','IM033','IM029','IM030','IM008','BFM026','BFM037','BFM025','BFM028','M024','M047','M044','M021'],
'T1036.003': ['M001','M018','IM017','IM034','IM012','IM033','IM021','IM029','IM030','IM008','BFM026','BFM028','BFM037','BFM019','BFM020','M024','M047','M044','M021'],
'T1036.004': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM020','BFM026','BFM028','BFM037','M024','M047','M044','M021'],
'T1036.005': ['M001','M018','IM017','IM034','IM033','IM012','IM021','IM029','IM030','IM008','BFM026','BFM028','BFM037','BFM019','M024','M047','M044','M021'],
'T1036.006': ['M001','M018','IM017','IM034','IM012','IM033','IM021','IM029','IM030','IM008','BFM026','BFM028','BFM037','M024','M047','M044','M021'],
'T1036.007': ['M001','M018','IM017','IM034','IM012','IM033','IM021','IM011','IM029','IM030','IM008','BFM026','BFM028','BFM037','M024','M047','M044','M021'],
'T1036.008': ['M001','M018','IM017','IM034','IM012','IM033','IM021','IM029','IM030','IM008','BFM026','BFM037','BFM025','BFM028','M024','M047','M044','M021'],
'T1036.009': ['M001','M018','IM034','IM017','IM033','IM021','IM029','IM030','IM008','BFM019','BFM020','BFM026','BFM028','BFM037','M024','M047','M044','M021'],
'T1036.010': ['M001','M018','IM022','IM035','IM034','IM033','IM021','IM029','IM030','IM008','BFM019','BFM020','BFM026','BFM028','M003','M024','M047','M044','M021'],
'T1036.011': ['M001','M018','IM034','IM017','IM033','IM021','IM012','IM029','IM030','IM008','BFM019','BFM020','BFM026','BFM028','BFM037','M024','M047','M044','M021'],

'T1037': ['M001','M018','IM017','IM034','IM033','IM021','IM022','IM008','IM029','IM030','BFM026','BFM025','BFM028','BFM020','BFM037','M025','M024','M047','M044','M021'],
'T1037.001': ['M001','M018','IM017','IM034','IM033','IM022','IM021','IM008','IM029','IM030','BFM026','BFM020','BFM028','BFM037','BFM025','M025','M024','M047','M044','M021'],
'T1037.002': ['M001','M018','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM026','BFM028','BFM025','BFM020','BFM019','BFM037','M025','M024','M047','M044','M021'],
'T1037.003': ['M001','M018','IM022','IM040','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM026','BFM020','BFM028','BFM037','M025','M024','M047','M044','M021'],
'T1037.004': ['M001','M018','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM020','BFM026','BFM028','BFM025','BFM037','M025','M024','M047','M044','M021'],
'T1037.005': ['M001','M018','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM026','BFM025','BFM028','BFM037','BFM020','M025','M024','M047','M044','M021'],

'T1048': ['M001','M018','IM014','IM012','IM011','IM021','IM033','IM034','IM008','IM029','IM030','IM032','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','M016','M019','M024','M047','M017','M044','M021'],
'T1048.001': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM008','IM029','IM030','IM032','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','M016','M019','M024','M047','M017','M044','M021'],
'T1048.002': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM008','IM029','IM030','IM032','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','M016','M019','M024','M047','M017','M044','M021'],
'T1048.003': ['M001','M018','IM014','IM012','IM011','IM021','IM033','IM034','IM008','IM029','IM030','IM032','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','M016','M019','M024','M047','M017','M044','M021'],

'T1052': ['M023','M001','M018','BFM016','BFM019','IM017','IM034','IM021','IM008','IM029','IM030','IM033','BFM026','BFM025','BFM028','BFM037','PFM023','PFM031','M017','M024','M047','M044','M021'],
'T1052.001': ['M023','M001','M018','BFM016','BFM019','IM017','IM034','IM021','IM008','IM029','IM030','IM033','BFM026','BFM025','BFM028','BFM037','PFM023','PFM031','M017','M024','M047','M044','M021'],

'T1053': ['M001','M018','IM022','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM025','BFM028','BFM037','M025','M024','M047','M044','M021'],
'T1053.001': ['M001','M018','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM025','BFM028','BFM037','M025','M024','M047','M044','M021'],
'T1053.002': ['M001','M018','IM022','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM025','BFM028','BFM037','M025','M024','M047','M044','M021'],
'T1053.003': ['M001','M018','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM025','BFM028','BFM037','M025','M024','M047','M044','M021'],
'T1053.004': ['M001','M018','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM025','BFM028','BFM037','M025','M024','M047','M044','M021'],
'T1053.005': ['M001','M018','IM022','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM025','BFM028','BFM037','M025','M024','M047','M044','M021'],
'T1053.006': ['M001','M018','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM025','BFM028','BFM037','M025','M024','M047','M044','M021'],
'T1053.007': ['M001','M018','IM040','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM025','BFM028','BFM037','M025','M024','M047','M044','M021'],

'T1055': ['M001','IM012','IM017','IM034','IM033','IM021','IM014','IM011','IM032','IM029','IM030','IM008','BFM016','BFM019','BFM026','M027','M007','M019','M016','M025','M047','M044','M021'],
'T1055.001': ['M001','IM012','IM017','IM034','IM033','IM021','IM014','IM011','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM037','PFM019','PFM010','PFM044','M027','M007','M019','M016','M025','M047','M044','M021'],
'T1055.002': ['M001','IM012','IM017','IM034','IM033','IM021','IM014','IM011','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM037','PFM019','PFM010','PFM044','M027','M007','M019','M016','M025','M047','M044','M021'],
'T1055.003': ['M001','IM012','IM017','IM034','IM033','IM021','IM014','IM011','IM029','IM030','IM008','BFM016','BFM019','BFM020','PFM019','PFM010','M027','M007','M019','M016','M025','M047','M044','M021'],
'T1055.004': ['M001','IM012','IM017','IM034','IM033','IM021','IM014','IM011','IM029','IM030','IM008','BFM016','BFM019','BFM020','PFM019','PFM010','M027','M007','M019','M016','M025','M047','M044','M021'],
'T1055.005': ['M001','IM012','IM017','IM034','IM033','IM021','IM014','IM011','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM037','PFM019','PFM010','M027','M007','M019','M016','M025','M047','M044','M021'],
'T1055.008': ['M001','IM012','IM017','IM034','IM033','IM021','IM014','IM011','IM029','IM030','IM008','BFM016','BFM019','PFM019','PFM010','PFM044','M027','M007','M019','M016','M025','M047','M044','M021'],
'T1055.009': ['M001','IM012','IM017','IM034','IM033','IM021','IM014','IM011','IM029','IM030','IM008','BFM016','BFM019','PFM019','PFM010','PFM044','M027','M007','M019','M016','M025','M047','M044','M021'],
'T1055.011': ['M001','IM012','IM017','IM034','IM033','IM021','IM014','IM011','IM029','IM030','IM008','BFM016','BFM019','BFM020','PFM019','PFM010','M027','M007','M019','M016','M025','M047','M044','M021'],
'T1055.012': ['M001','IM012','IM017','IM034','IM033','IM021','IM014','IM011','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM037','PFM019','PFM010','PFM044','M027','M007','M019','M016','M025','M047','M044','M021'],
'T1055.013': ['M001','IM012','IM017','IM034','IM033','IM021','IM014','IM011','IM029','IM030','IM008','BFM016','BFM019','BFM026','PFM019','PFM010','PFM044','M027','M007','M019','M016','M025','M047','M044','M021'],
'T1055.014': ['M001','IM012','IM017','IM034','IM033','IM021','IM014','IM011','IM029','IM030','IM008','BFM016','BFM019','PFM019','PFM010','PFM44','M027','M007','M019','M016','M025','M047','M044','M021'],
'T1055.015': ['M001','IM012','IM017','IM034','IM033','IM021','IM014','IM011','IM029','IM030','IM008','BFM016','BFM019','BFM020','M027','M007','M019','M016','M025','M047','M044','M021'],

'T1056': ['M001','M018','M004','M028','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M025','M047','M017','M044','M021'],
'T1056.001': ['M001','M018','M004','M028','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM026','BFM028','BFM025','BFM037','PFM019','PFM010','PFM044','M024','M025','M047','M017','M044','M021'],
'T1056.002': ['M001','M018','M004','M028','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M025','M047','M017','M044','M021'],
'T1056.003': ['M001','M018','M004','M028','IM022','IM017','IM034','IM033','IM021','IM012','IM014','IM011','IM008','IM029','IM030','BFM016','BFM019','BFM024','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M025','M047','M017','M044','M021'],
'T1056.004': ['M001','M018','M004','M028','IM017','IM034','IM033','IM021','IM012','IM022','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M025','M047','M017','M044','M021'],

'T1059': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM014','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M017','M044','M021'],
'T1059.001': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM014','IM008','IM029','IM030','IM040','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M017','M044','M021'],
'T1059.002': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M017','M044','M021'],
'T1059.003': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM014','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M017','M044','M021'],
'T1059.004': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M017','M044','M021'],
'T1059.005': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM014','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M017','M044','M021'],
'T1059.006': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M017','M044','M021'],
'T1059.007': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM014','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M017','M044','M021'],
'T1059.008': ['M001','M018','IM017','IM034','IM033','IM021','IM014','IM012','IM008','IM029','IM030','IM040','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M017','M044','M021'],
'T1059.009': ['M001','M018','M003','M028','IM022','IM040','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','PFM019','PFM010','PFM044','M024','M047','M017','M044','M021'],
'T1059.010': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','PFM019','PFM010','PFM044','M024','M047','M017','M044','M021'],
'T1059.011': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M017','M044','M021'],
'T1059.012': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM014','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M017','M044','M021'],

'T1069': ['M001','M018','IM022','IM035','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','M024','M047','M044','M021'],
'T1069.001': ['M001','M018','IM022','IM035','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','M024','M047','M044','M021'],
'T1069.002': ['M001','M018','IM022','IM040','IM035','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','M024','M047','M044','M021'],
'T1069.003': ['M003','M018','M028','IM022','IM040','IM035','IM033','IM021','IM008','IM029','IM030','M024','M047','M044','M021'],

'T1070': ['M001','M018','IM022','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1070.001': ['M001','M018','IM022','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1070.002': ['M001','M018','IM022','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1070.003': ['M001','M018','IM022','IM034','IM033','IM021','IM014','IM008','IM029','IM030','IM032','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1070.004': ['M001','M018','IM022','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM031','PFM044','M017','M022','M024','M047','M044','M021'],
'T1070.005': ['M001','M018','IM022','IM034','IM033','IM021','IM014','IM008','IM029','IM030','IM032','BFM016','BFM019','BFM020','BFM009','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1070.006': ['M001','M018','IM022','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM031','PFM044','M024','M047','M044','M021'],
'T1070.007': ['M001','M018','IM022','IM034','IM033','IM021','IM011','IM014','IM008','IM029','IM030','IM032','BFM016','BFM019','BFM020','BFM009','BFM026','BFM027','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1070.008': ['M003','M018','M028','IM022','IM040','IM038','IM008','IM029','IM030','M017','M022','M024','M047','M044','M021'],
'T1070.009': ['M001','M018','IM022','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM025','BFM028','BFM037','PFM019','PFM010','PFM044','M025','M024','M047','M044','M021'],
'T1070.010': ['M003','M018','M004','M028','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','PFM019','PFM010','PFM044','M024','M047','M044','M021'],

'T1071': ['M001','M018','IM014','IM012','IM011','IM021','IM033','IM034','IM032','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM028','BFM026','BFM037','PFM019','PFM010','PFM044','M016','M019','M024','M047','M017','M044','M021'],
'T1071.001': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM032','IM008','IM029','IM030','IM011','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','M016','M019','M024','M047','M017','M044','M021'],
'T1071.002': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM032','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM028','BFM026','BFM037','M016','M019','M024','M047','M017','M044','M021'],
'T1071.003': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM011','IM038','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM028','BFM026','BFM037','M019','M024','M047','M017','M044','M021'],
'T1071.004': ['M001','M018','IM011','IM014','IM021','IM033','IM034','IM032','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM027','BFM028','BFM026','BFM037','M019','M016','M024','M047','M017','M044','M021'],
'T1071.005': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M016','M024','M047','M017','M044','M021'],

'T1074': ['M001','M018','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM026','BFM037','BFM028','BFM025','M017','M024','M047','M044','M021'],
'T1074.001': ['M001','M018','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM026','BFM028','BFM037','BFM025','M017','M024','M047','M044','M021'],
'T1074.002': ['M001','M018','IM017','IM034','IM033','IM021','IM014','IM012','IM032','IM008','IM029','IM030','BFM016','BFM026','BFM028','BFM037','BFM025','BFM009','M016','M019','M017','M024','M047','M044','M021'],

'T1078': ['M003','M018','M028','M004','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','M024','M047','M017','M044','M021'],
'T1078.001': ['M003','M018','M028','M004','IM022','IM034','IM021','IM008','IM029','IM030','BFM016','BFM019','M024','M047','M017','M044','M021'],
'T1078.002': ['M003','M018','M028','M004','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','M024','M047','M017','M044','M021'],
'T1078.003': ['M001','M018','M004','IM022','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','M024','M047','M017','M044','M021'],
'T1078.004': ['M003','M018','M028','M004','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','M024','M047','M017','M044','M021'],

'T1087': ['M001','M018','IM022','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','M024','M044','M047','M021'],
'T1087.001': ['M001','M018','IM022','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','M024','M044','M047','M021'],
'T1087.002': ['M001','M018','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','M024','M044','M047','M021'],
'T1087.003': ['M003','M018','M028','IM022','IM040','IM038','IM008','IM029','IM030','M024','M044','M047','M021'],
'T1087.004': ['M003','M018','M028','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','M024','M044','M047','M021'],

'T1090': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM032','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM028','BFM026','M016','M019','M024','M047','M017','M044','M021'],
'T1090.001': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM011','IM032','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM028','BFM026','M016','M019','M024','M047','M017','M044','M021'],
'T1090.002': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM032','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM028','BFM026','M016','M019','M024','M047','M017','M044','M021'],
'T1090.003': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM032','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM028','BFM026','PFM019','PFM010','PFM044','M016','M019','M024','M047','M017','M044','M021'],
'T1090.004': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM032','IM011','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM028','BFM026','M016','M019','M024','M047','M017','M044','M021'],

'T1098': ['M003','M018','M028','M004','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','M025','M024','M047','M017','M044','M021'],
'T1098.001': ['M003','M018','M028','M004','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','M025','M024','M047','M017','M044','M021'],
'T1098.002': ['M003','M018','M028','M004','IM022','IM040','IM038','IM034','IM021','IM008','IM029','IM030','BFM016','M025','M024','M047','M017','M044','M021'],
'T1098.003': ['M003','M018','M028','M004','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','M025','M024','M047','M017','M044','M021'],
'T1098.004': ['M003','M018','M028','M004','IM022','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','M025','M024','M047','M017','M044','M021'],
'T1098.005': ['M003','M018','M028','M004','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','M025','M024','M047','M017','M044','M021'],
'T1098.006': ['M003','M018','M028','M004','IM022','IM040','IM033','IM021','IM008','IM029','IM030','BFM016','M025','M024','M047','M017','M044','M021'],
'T1098.007': ['M003','M018','M028','M004','IM022','IM040','IM033','IM021','IM008','IM029','IM030','BFM016','M025','M024','M047','M017','M044','M021'],

'T1102': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM032','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','M016','M019','M024','M047','M017','M044','M021'],
'T1102.001': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM011','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','M016','M019','M024','M047','M017','M044','M021'],
'T1102.002': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM032','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','PFM019','PFM010','PFM044','M016','M019','M024','M047','M017','M044','M021'],
'T1102.003': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','M016','M019','M024','M047','M017','M044','M021'],

'T1110': ['M001','M018','M004','M028','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','M024','M047','M017','M044','M021'],
'T1110.001': ['M001','M018','M004','M028','IM022','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','M024','M047','M017','M044','M021'],
'T1110.002': ['M001','M018','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM037','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1110.003': ['M001','M018','M004','M028','IM022','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','M024','M047','M017','M044','M021'],
'T1110.004': ['M001','M018','M004','M028','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','M024','M047','M017','M044','M021'],

'T1114': ['M001','M018','M004','M028','IM022','IM040','IM038','IM012','IM014','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM024','M017','M024','M047','M044','M021'],
'T1114.001': ['M001','M018','IM017','IM034','IM033','IM021','IM038','IM008','IM029','IM030','BFM016','BFM019','BFM024','BFM026','BFM028','M017','M024','M047','M044','M021'],
'T1114.002': ['M001','M018','M004','M028','IM022','IM040','IM038','IM014','IM021','IM008','IM029','IM030','BFM016','BFM019','M017','M024','M047','M044','M021'],
'T1114.003': ['M003','M018','M028','IM022','IM040','IM038','IM008','IM029','IM030','M017','M024','M047','M044','M021'],

'T1127': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1127.001': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1127.002': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM026','BFM028','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1127.003': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM026','BFM028','PFM019','PFM010','PFM044','M024','M047','M044','M021'],

'T1132': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM032','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM028','BFM026','M016','M019','M024','M047','M017','M044','M021'],
'T1132.001': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','M016','M019','M024','M047','M017','M044','M021'],
'T1132.002': ['M001','M018','IM014','IM012','IM021','IM033','IM034','IM032','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM028','BFM026','M016','M019','M024','M047','M017','M044','M021'],

'T1134': ['M001','M018','IM022','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1134.001': ['M001','M018','IM022','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM028','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1134.002': ['M001','M018','IM022','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM020','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1134.003': ['M001','M018','IM022','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM028','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1134.004': ['M001','M018','IM034','IM033','IM021','IM017','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1134.005': ['M003','M018','M028','M004','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','PFM019','PFM010','PFM044','M024','M047','M044','M021'],

'T1136': ['M003','M018','M004','M028','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','M025','M024','M047','M044','M021'],
'T1136.001': ['M001','M018','IM022','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','M025','M024','M047','M044','M021'],
'T1136.002': ['M003','M018','M028','M004','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','M025','M024','M047','M044','M021'],
'T1136.003': ['M003','M018','M028','M004','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','M025','M024','M047','M044','M021'],

'T1137': ['M001','M018','IM017','IM034','IM033','IM021','IM038','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM026','BFM025','BFM028','BFM037','M025','M024','M047','M044','M021'],
'T1137.001': ['M001','M018','IM017','IM034','IM033','IM021','IM038','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM026','BFM025','BFM028','BFM037','M025','M024','M047','M044','M021'],
'T1137.002': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM026','BFM028','BFM037','M025','M024','M047','M044','M021'],
'T1137.003': ['M001','M018','IM017','IM034','IM033','IM021','IM038','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM026','BFM025','BFM028','M025','M024','M047','M044','M021'],
'T1137.004': ['M001','M018','IM017','IM034','IM033','IM021','IM038','IM012','IM014','IM008','IM029','IM030','BFM016','BFM019','BFM026','BFM025','BFM028','M025','M024','M047','M044','M021'],
'T1137.005': ['M001','M018','IM017','IM034','IM033','IM021','IM038','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM026','BFM028','M025','M024','M047','M044','M021'],
'T1137.006': ['M001','M018','IM017','IM034','IM033','IM021','IM038','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM026','BFM028','BFM037','M025','M024','M047','M044','M021'],

'T1176': ['M001','M018','IM017','IM034','IM033','IM021','IM014','IM012','IM038','IM008','IM029','IM030','BFM016','BFM019','BFM024','BFM026','BFM028','M025','M047','M024','M017','M044','M021'],
'T1176.001': ['M001','M018','IM017','IM034','IM033','IM021','IM014','IM012','IM038','IM008','IM029','IM030','BFM016','BFM019','BFM024','BFM026','BFM028','M025','M047','M024','M017','M044','M021'],
'T1176.002': ['M001','M018','IM017','IM034','IM033','IM021','IM014','IM012','IM038','IM008','IM029','IM030','BFM016','BFM019','BFM024','BFM026','BFM028','M025','M047','M024','M017','M044','M021'],

'T1195': ['IM012','IM017','IM014','IM032','M016','M001','IM033','IM008','IM011','IM029','IM039','IM021','IM034','IM013','BFM016','BFM019','BFM037','M025','M020','M026','M024','M047','M044','M021'],
'T1195.001': ['IM012','IM017','IM014','IM032','M016','M001','IM033','IM008','IM029','IM039','IM021','IM034','IM013','IM036','BFM016','BFM019','BFM020','BFM037','M025','M027','M020','M026','M024','M047','M044','M021'],
'T1195.002': ['IM012','IM017','IM014','IM032','M039','M016','M001','IM033','IM008','IM011','IM029','IM039','IM021','IM022','IM034','IM013','IM036','M025','M027','M020','M0XX','M026','M037','M045','M044'],
'T1195.003': ['IM017','IM034','IM033','IM012','IM014','IM032','M016','M001','IM008','IM029','IM039','IM021','BFM016','BFM019','BFM037','PFM019','PFM010','M025','M020','M024','M047','M044','M021'],

'T1204': ['IM004','IM012','IM017','IM003','IM029','IM021','IM014','IM011','IM034','IM008','M008','M019','M016','M007','M012','M004','M018','M017','M047','M044'],
'T1204.001': ['IM004','IM012','IM029','IM003','IM021','IM014','IM011','IM008','IM034','M008','M019','M016','M007','M012','M004','M018','M044'],
'T1204.002': ['M001','BFM016','BFM019','IM012','IM017','IM003','IM029','IM021','IM014','IM011','IM034','IM033','IM032','IM008','M007','M019','M016','M004','M018','M017','M047','M005','M044'],
'T1204.003': ['M001','BFM016','BFM019','IM004','IM012','IM017','IM003','IM029','IM021','IM014','IM011','IM034','IM033','IM032','IM008','M007','M019','M016','M004','M018','M017','M047','M005','M044'],
'T1204.004': ['M001','BFM016','BFM019','IM004','IM012','IM017','IM003','IM029','IM021','IM014','IM011','IM034','IM033','IM032','IM008','IM025','M007','M019','M016','M004','M018','M017','PFM019','PFM044','M047','M005','M044'],

'T1205': ['M001','BFM019','BFM009','PFM019','IM017','IM029','IM032','IM034','IM021','IM011','IM013','IM012','M016','M039','M017','M027','M048','M020','M044'],
'T1205.001': ['M001','BFM009','IM017','IM029','IM032','IM034','IM021','IM011','IM013','IM012','M016','M039','M017','M027','M048','M020','M044'],
'T1205.002': ['M001','BFM019','BFM009','PFM019','IM017','IM029','IM032','IM034','IM021','IM011','IM013','IM012','M016','M039','M017','M027','PFM045','M048','M020','M044'],
    
'T1213': ['M001','M018','IM022','IM040','IM034','IM033','IM021','IM012','IM014','IM008','IM029','IM030','BFM016','BFM019','BFM024','M017','M024','M047','M044','M021'],
'T1213.001': ['M001','M018','IM022','IM040','IM034','IM033','IM021','IM014','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM024','M017','M024','M047','M044','M021'], 
'T1213.002': ['M001','M018','IM022','IM040','IM034','IM033','IM021','IM014','IM012','IM038','IM008','IM029','IM030','BFM016','BFM019','BFM024','BFM026','M017','M024','M047','M044','M021'], 
'T1213.003': ['M001','M018','IM022','IM040','IM034','IM033','IM021','IM012','IM014','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM026','PFM019','M017','M024','M047','M044','M021'], 
'T1213.004': ['M001','M018','IM022','IM040','IM038','IM034','IM033','IM021','IM008','IM029','IM030','BFM024','BFM016','BFM019','M017','M024','M047','M044','M021'], 
'T1213.005': ['M003','M018','M028','IM022','IM040','IM034','IM033','IM021','IM029','IM030','IM008','BFM016','BFM019','M017','M024','M047','M044','M021'],

'T1216': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','BFM037','M024','M047','M044','M021'],
'T1216.001': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','BFM037','M024','M047','M044','M021'],
'T1216.002': ['M001','M018','IM017','IM034','IM033','IM021','IM040','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','BFM037','M024','M047','M044','M021'],

'T1218': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM014','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1218.001': ['M001','M018','IM017','IM034','IM033','IM012','IM021','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','BFM037','M024','M047','M044','M021'], 
'T1218.002': ['M001','M018','IM017','IM034','IM033','IM012','IM021','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','M024','M047','M044','M021'], 
'T1218.003': ['M001','M018','IM017','IM034','IM033','IM012','IM014','IM021','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','BFM037','M024','M047','M044','M021'], 
'T1218.004': ['M001','M018','IM017','IM034','IM033','IM012','IM021','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','M024','M047','M044','M021'], 
'T1218.005': ['M001','M018','IM017','IM034','IM033','IM012','IM021','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','PFM019','PFM010','PFM044','M024','M047','M044','M021'], 
'T1218.007': ['M001','M018','IM017','IM034','IM033','IM012','IM021','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','M024','M047','M044','M021'], 
'T1218.008': ['M001','M018','IM017','IM034','IM033','IM012','IM021','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','M024','M047','M044','M021'], 
'T1218.009': ['M001','M018','IM017','IM034','IM033','IM012','IM021','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','M024','M047','M044','M021'], 
'T1218.010': ['M001','M018','IM017','IM034','IM033','IM012','IM021','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','M024','M047','M044','M021'], 
'T1218.011': ['M001','M018','IM017','IM034','IM033','IM012','IM021','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM026','BFM028','PFM019','PFM010','PFM044','M024','M047','M044','M021'], 
'T1218.012': ['M001','M018','IM017','IM034','IM033','IM012','IM021','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','M024','M047','M044','M021'], 
'T1218.013': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM026','BFM028','PFM019','PFM010','PFM044','M024','M047','M044','M021'], 
'T1218.014': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM020','BFM026','BFM028','M024','M047','M044','M021'], 
'T1218.015': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM029','IM030','IM008','BFM016','BFM019','BFM026','BFM028','M024','M047','M044','M021'], 

'T1219': ['M001','M018','IM017','IM034','IM033','IM021','IM014','IM012','IM040','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','M016','M019','M024','M047','M017','M044','M021'],
'T1219.001': ['M001','M018','IM017','IM038','IM034','IM033','IM021','IM014','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM024','BFM026','BFM028','M016','M019','M024','M047','M017','M044','M021'],
'T1219.002': ['M001','M018','IM017','IM034','IM033','IM021','IM014','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','M016','M019','M024','M047','M017','M044','M021'],
'T1219.003': ['M003','M018','M028','IM022','IM040','IM017','IM034','IM033','IM021','IM014','IM012','IM008','IM029','IM030','BFM016','BFM019','M016','M019','M024','M047','M017','M044','M021'],

'T1222': ['M001','M018','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','M025','M024','M047','M044','M021'],
'T1222.001': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM026','BFM028','BFM037','M025','M024','M047','M044','M021'],
'T1222.002': ['M001','M018','IM017','IM034','IM033','IM021','IM032','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','M025','M024','M047','M044','M021'],

'T1480': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM028','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1480.001': ['M001','M018','IM017','IM034','IM033','IM022','IM040','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM028','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1480.002': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM028','PFM019','PFM010','PFM044','M024','M047','M044','M021'],

'T1484': ['M003','M018','M028','M004','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1484.001': ['M003','M018','M028','M004','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1484.002': ['M003','M018','M028','M004','IM022','IM040','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','PFM019','PFM010','PFM044','M024','M047','M044','M021'],

'T1485': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM028','BFM026','BFM037','IM041','M017','M022','M024','M047','M044','M021'],
'T1485.001': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM028','BFM026','BFM037','IM041','M017','M022','M024','M047','M044','M021'],

'T1486':      ['M001','M002','IM017','M029','M007','M003','IM003','IM039','M024','IM033','IM032','BFM020','PFM042','IM021','IM014','IM011','IM007','IM022','M017','IM041','M005','M043','M045'],

'T1491': ['M001','M018','IM014','IM012','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM024','BFM026','BFM028','M016','M019','M024','M047','M044','M021'],
'T1491.001': ['M001','M018','IM022','IM040','IM014','IM017','IM034','IM033','IM021','IM038','IM008','IM029','IM030','BFM016','BFM019','BFM024','BFM026','M016','M019','M024','M047','M044','M021'],
'T1491.002': ['M001','M018','IM014','IM012','IM017','IM034','IM033','IM021','IM008','IM029','IM030','BFM016','BFM019','BFM024','BFM026','BFM028','BFM037','M016','M019','M024','M047','M044','M021'],

'T1496': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM014','IM032','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','BFM037','M016','M019','M024','M047','M044','M021'],
'T1496.001': ['M003','M018','M028','IM022','IM040','IM017','IM034','IM033','IM021','IM014','IM012','IM008','IM029','IM030','BFM016','BFM020','BFM019','M016','M019','M024','M047','M044','M021'],
'T1496.002': ['M003','M018','IM022','IM040','IM017','IM034','IM033','IM021','IM014','IM012','IM032','IM008','IM029','IM030','BFM016','BFM020','BFM019','BFM028','M016','M019','M024','M047','M044','M021'],
'T1496.003': ['M001','M018','IM017','IM034','IM033','IM021','IM014','IM012','IM032','IM008','IM029','IM030','BFM016','BFM020','BFM019','BFM026','M016','M019','M024','M047','M044','M021'],
'T1496.004': ['M001','M018','IM017','IM034','IM033','IM021','IM032','IM012','IM014','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM026','BFM028','M025','M016','M019','M024','M047','M044','M021'],
    
'T1497': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1497.001': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','BFM037','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1497.002': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','PFM019','PFM010','PFM044','M024','M047','M044','M021'],
'T1497.003': ['M001','M018','IM017','IM034','IM033','IM021','IM012','IM008','IM029','IM030','BFM016','BFM019','BFM020','PFM019','PFM010','PFM044','M024','M047','M044','M021'],

'T1498': ['IM001','M001','BFM016','BFM019','M016','IM008','IM021','BFM009','IM032','IM014','IM012','IM029','IM030','IM034','IM033','BFM020','BFM028','M019','M024','M047','M044','M021'],
'T1498.001': ['IM001','M001','BFM016','BFM019','M016','IM008','IM021','BFM009','IM032','IM029','IM030','IM034','IM013','BFM025','M025','IM016','IM039','IM041','M005'],
'T1498.002': ['IM001','M001','BFM016','BFM019','M016','IM008','IM021','BFM009','IM032','IM014','IM012','IM029','IM030','IM034','IM033','M019','M024','M047','M044','M021'],

'T1499':      ['M001','M014','IM001','PFM019','M021'],                 
'T1499.002':  ['M017','M001','M014','IM001','PFM019'],
'T1499.003':  ['IM021','M016','M008','IM008','IM039'],
'T1499.004':  ['M001','M020','M016','PFM019'], 

'T1505':     ['M001','IM017','IM029','IM003','IM012','IM021','IM033','IM032','IM034','IM025','IM028','IM013','IM036','IM022','IM014','IM011','BFM020','BFM028','BFM025','BFM026','BFM016','BFM019','PFM019','PFM045','PFM006','M002','M007','M027','M016','M039','M004','M018','M028','M045','IM041','M020','M037','M041','M044'],
'T1505.001': ['M001','IM017','IM029','IM003','IM012','IM008','IM021','IM033','IM032','IM025','IM013','IM036','IM022','IM014','BFM020','BFM028','BFM025','BFM026','BFM016','BFM019','PFM019','PFM045','PFM006','M002','M025','M027','M016','M039','M004','M018','M026','M045','IM041','M020','M037','M041','M044'],
'T1505.002': ['M001','IM017','IM029','IM003','IM012','IM038','IM008','IM021','IM033','IM032','IM034','IM013','IM022','IM014','IM011','BFM020','BFM028','BFM025','BFM026','BFM016','BFM019','PFM019','PFM045','PFM006','M002','M012','M006','M008','M019','M007','M027','M016','M039','M004','M018','M028','M045','IM041','M020','M037','M041','M044'],
'T1505.003': ['M001','IM017','IM029','IM003','IM012','IM008','IM021','IM033','IM032','IM034','IM025','IM028','IM013','IM036','IM022','IM014','IM011','BFM020','BFM028','BFM025','BFM026','BFM016','BFM019','PFM019','PFM045','PFM006','M002','M007','M027','M016','M039','M004','M018','M028','M045','IM041','M020','M037','M041','M044'],
'T1505.004': ['M001','IM017','IM029','IM003','IM012','IM008','IM021','IM033','IM032','IM034','IM025','IM028','IM013','IM036','IM022','IM014','IM011','BFM020','BFM028','BFM025','BFM026','BFM037','BFM016','BFM019','PFM019','PFM045','PFM006','M002','M007','M027','M016','M039','M004','M018','M028','M045','IM041','M020','M037','M041','M044'],
'T1505.005': ['M001','IM017','IM029','IM003','IM012','IM021','IM033','IM032','IM034','IM013','IM036','IM022','IM014','BFM017','BFM020','BFM028','BFM025','BFM026','BFM016','BFM019','PFM043','PFM031','PFM019','PFM045','PFM006','M002','M007','M027','M016','M039','M004','M018','M028','M045','IM041','M020','M037','M041','M044'],
'T1505.006': ['M001','IM017','IM029','IM003','IM012','IM040','IM008','IM021','IM033','IM032','IM013','IM036','IM022','IM014','BFM020','BFM028','BFM025','BFM026','BFM016','BFM019','PFM019','PFM045','PFM006','M002','M007','M027','M016','M039','M026','M037','M042','M048','M043','IM041','M020','M041','M044'],

'T1518':     ['IM021','IM032','IM017','IM029','IM003','IM012','IM011','IM013','IM034','BFM019','PFM019','BFM009','M001','M027','M016','M039','M017','M044'],
'T1518.001': ['IM021','IM017','IM029','IM003','IM012','IM040','IM011','IM013','BFM019','PFM019','IM034','BFM009','M016','M027','M039','M017','M044'],

'T1542':     ['M001','BFM016','BFM019','PFM019','PFM044','PFM045','IM017','IM029','IM003','IM012','IM028','IM013','BFM037','IM034','IM021','M025','M027','M007','M047','M005','M048','M043','M020','M037','M041','M044'],
'T1542.001': ['M001','BFM016','BFM019','PFM019','PFM044','PFM045','IM017','IM029','IM003','IM012','BFM037','IM028','IM013','IM034','IM021','M025','M048','M043','M020','M037','M041','M044'],
'T1542.002': ['M001','BFM016','BFM019','PFM019','PFM044','PFM045','IM017','IM029','IM003','IM012','IM028','IM013','BFM037','IM034','IM021','M025','M047','M005','M043','M020','M037','M041','M044'],
'T1542.003': ['M001','BFM016','BFM019','PFM019','PFM044','PFM045','IM017','IM029','IM003','IM012','IM028','IM013','PFM031','BFM037','IM034','IM021','M025','M027','M007','M047','M005','M043','M020','M041','M044'],
'T1542.004': ['M001','M002','BFM016','BFM019','PFM019','PFM044','PFM045','IM017','IM029','IM003','IM012','IM021','IM014','IM008','IM028','IM013','M016','M039','M025','M047','M048','M020','M041','M044'],
'T1542.005': ['M001','BFM016','BFM019','PFM019','PFM044','IM017','IM029','IM003','IM012','IM021','IM014','IM008','IM028','IM013','M008','M019','M016','M039','M025','M047','M020','M041','M044'],

'T1543': ['M001','IM017','IM029','IM003','IM012','M017','IM028','IM013','IM034','IM021','BFM017','BFM025','BFM026','BFM037','PFM019','PFM044','PFM045','M025','M027','M007','M047','M048','M020','M041','M044'],
'T1543.001': ['M001','IM017','IM029','IM003','IM012','M017','IM013','BFM017','BFM025','BFM026','IM034','IM021','PFM019','M025','M027','M007','M047','M020','M041','M044'],
'T1543.002': ['M001','IM017','IM029','IM003','IM012','M017','IM013','IM028','IM034','IM021','BFM019','PFM019','PFM044','M025','M027','M007','M047','M048','M020','M044'],
'T1543.003': ['M001','IM017','IM029','IM003','IM012','M017','IM013','IM028','IM034','IM021','BFM017','BFM025','BFM037','PFM045','M025','M027','M007','M047','M020','M041','M044'],
'T1543.004': ['M001','IM017','IM029','IM003','IM012','M017','IM013','BFM017','BFM025','IM034','IM021','PFM019','M025','M027','M007','M047','M048','M020','M044'],
'T1543.005': ['M001','IM017','IM029','IM003','IM012','M017','IM013','IM040','IM021','BFM019','PFM019','PFM044','IM034','M025','M027','M007','M047','M043','M020','M044'],

'T1546': ['M001','IM017','IM029','IM003','IM012','M017','IM028','IM013','IM021','IM034','BFM017','BFM025','BFM026','BFM037','M025','M027','M007','M020','M041','M045','M044'],
'T1546.001': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M007','M025','M004','M018','M044'],
'T1546.002': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M007','M025','M020','M044'],
'T1546.003': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','BFM020','BFM025','M025','M027','M020','M044'],
'T1546.004': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M025','M027','M020','M044'],
'T1546.005': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','PFM019','M025','M027','M020','M044'],
'T1546.006': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M025','M027','M020','M044'],
'T1546.007': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M025','M027','M020','M044'],
'T1546.008': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M025','M027','M020','M044'],
'T1546.009': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M025','M027','M020','M044'],
'T1546.010': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M025','M027','M020','M044'],
'T1546.011': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M025','M027','M020','M044'],
'T1546.012': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M025','M027','M020','M044'],
'T1546.013': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M025','M027','M020','M044'],
'T1546.014': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M025','M027','M020','M044'],
'T1546.015': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M025','M027','M020','M044'],
'T1546.016': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M025','M027','M020','M044'],
'T1546.017': ['M001','IM017','IM029','IM003','IM012','M017','IM021','IM014','IM008','M025','M027','M020','M044'],

'T1547': ['M001','IM017','IM029','IM003','IM012','M017','IM028','IM036','IM013','BFM017','BFM025','BFM026','BFM037','IM034','IM021','M025','M027','M007','M047','M020','M041','M045','M044'],
'T1547.001': ['M001','IM017','IM029','IM003','IM012','M017','IM028','IM036','BFM017','BFM025','BFM026','BFM037','IM034','IM021','M025','M007','M027','M047','M020','M041','M045','M044'],
'T1547.002': ['M001','PFM019','PFM044','IM017','IM029','IM003','IM012','M017','IM028','BFM017','IM034','IM021','M025','M027','M007','M047','M004','M018','M020','M045','M044'],
'T1547.003': ['M001','IM017','IM029','IM003','IM012','M017','IM013','BFM017','IM028','IM034','IM021','M025','M027','M007','M047','M020','M044'],
'T1547.004': ['M001','IM017','IM029','IM003','IM012','M017','BFM017','IM028','IM036','IM034','IM021','M025','M027','M007','M047','M048','M020','M044'],
'T1547.005': ['M001','PFM019','PFM044','IM017','IM029','IM003','IM012','M017','BFM017','IM028','IM034','IM021','M025','M027','M007','M047','M004','M018','M048','M020','M044'],
'T1547.006': ['M001','PFM019','PFM044','PFM045','IM017','IM029','IM003','IM012','M017','IM028','BFM037','IM034','IM021','M027','M025','M048','M020','M044'],
'T1547.007': ['M001','IM017','IM029','IM003','IM012','M017','IM028','IM036','IM013','IM021','M025','M047','M020','M044'],
'T1547.008': ['M001','PFM019','PFM044','IM017','IM029','IM003','IM012','M017','IM028','BFM017','IM034','IM021','M025','M027','M048','M020','M044'],
'T1547.009': ['IM017','IM029','IM003','IM012','M017','IM021','BFM028','IM025','IM036','M007','M025','M047','M044'],
'T1547.010': ['M001','IM017','IM029','IM003','IM012','M017','BFM017','IM028','IM013','IM034','IM021','M025','M027','M041','M020','M044'],
'T1547.011': ['M001','IM017','IM029','IM003','IM012','M017','IM028','IM036','IM013','IM021','M025','M047','M020','M044'],
'T1547.012': ['M001','IM017','IM029','IM003','IM012','M017','BFM017','IM028','IM013','IM034','IM021','M025','M027','M041','M020','M044'],
'T1547.013': ['M001','IM017','IM029','IM003','IM012','M017','IM028','IM036','IM013','IM021','M025','M047','M020','M044'],
'T1547.014': ['M001','IM017','IM029','IM003','IM012','M017','BFM017','IM028','IM013','IM034','IM021','M025','M027','M020','M044'],
'T1547.015': ['M001','IM017','IM029','IM003','IM012','M017','IM028','IM036','IM013','IM021','M025','M047','M020','M044'],

'T1548': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM008','IM021','IM032','IM029','IM030','IM013','BFM025','IM016','IM039','M025','M024','M047','M044','M021'],
'T1548.001': ['IM001','M001','BFM016','BFM019','IM032','IM017','IM034','IM008','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M025','M024','M047','M044','M021'], 
'T1548.002': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM008','IM021','IM029','IM030','IM013','BFM026','BFM028','IM016','IM039','M025','M024','M047','M044','M021'], 
'T1548.003': ['IM001','M001','BFM016','BFM019','IM032','IM017','IM034','IM008','IM021','IM029','IM030','IM013','BFM020','BFM025','IM016','IM039','M025','M024','M047','M044','M021'], 
'T1548.004': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM008','IM021','IM029','IM030','IM013','BFM026','BFM028','IM016','IM039','M025','M024','M047','M044','M021'], 
'T1548.005': ['IM001','M001','BFM016','BFM019','IM032','IM017','IM034','IM008','IM021','IM029','IM030','IM013','BFM020','IM016','IM039','M025','M024','M047','M044','M021'], 
'T1548.006': ['IM001','M001','BFM016','BFM019','IM040','IM017','IM034','IM008','IM021','IM029','IM030','IM013','BFM020','BFM025','IM016','IM039','M025','M024','M047','M044','M021'], 
    
'T1550': ['IM001','M003','M018','M028','M004','IM022','IM040','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1550.001': ['IM001','M003','M018','M028','M004','IM022','IM040','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','IM038','IM016','IM039','M024','M047','M044','M021'], 
'T1550.002': ['IM001','M003','M018','M028','M004','IM022','BFM016','BFM019','BFM020','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','BFM028','IM016','IM039','M024','M047','M044','M021'], 
'T1550.003': ['IM001','M003','M018','M028','M004','IM022','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','BFM028','PFM019','PFM010','IM016','IM039','M024','M047','M044','M021'],  
'T1550.004': ['IM001','M003','M018','M028','M004','IM022','IM040','IM038','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],  
    
'T1552': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1552.001': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],  
'T1552.002': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','BFM028','IM016','IM039','M024','M047','M044','M021'], 
'T1552.003': ['IM001','M001','BFM016','BFM019','IM032','IM017','IM034','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'], 
'T1552.004': ['IM001','M003','M018','M028','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'], 
'T1552.005': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'], 
'T1552.006': ['IM001','M003','M018','M028','IM022','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','IM016','IM039','M024','M047','M044','M021'], 
'T1552.007': ['IM001','M003','M018','M028','IM022','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'], 
'T1552.008': ['IM001','M003','M018','M028','IM022','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM028','PFM019','PFM010','IM016','IM039','M024','M047','M044','M021'], 

'T1553': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M025','M024','M047','M044','M021'],
'T1553.001': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M025','M024','M047','M044','M021'], 
'T1553.002': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M025','M024','M047','M044','M021'],
'T1553.003': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M025','M024','M047','M044','M021'], 
'T1553.004': ['IM001','M001','BFM016','BFM019','BFM037','IM014','IM012','IM029','IM030','IM013','IM016','IM039','M025','M024','M047','M044','M021'], 
'T1553.005': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M025','M024','M047','M044','M021'], 
'T1553.006': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M025','M024','M047','M044','M021'], 

'T1555': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1555.001': ['IM001','M001','BFM016','BFM019','IM040','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM020','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1555.002': ['IM001','M001','BFM016','BFM019','BFM020','PFM019','PFM010','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1555.003': ['IM001','M001','BFM016','BFM019','IM038','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM024','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1555.004': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','BFM028','IM016','IM039','M024','M047','M044','M021'],
'T1555.005': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM038','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1555.006': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],

'T1556': ['IM001','M003','M018','M028','M004','IM022','IM040','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','PFM019','PFM010','IM016','IM039','M024','M047','M044','M021'],
'T1556.001': ['IM001','M003','M018','M028','M004','IM022','IM040','BFM016','BFM019','PFM019','PFM010','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1556.002': ['IM001','M003','M018','M028','M004','IM022','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','BFM028','PFM019','PFM010','IM016','IM039','M024','M047','M044','M021'],
'T1556.003': ['IM001','M003','M018','M028','M004','IM022','BFM016','BFM019','IM032','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM020','BFM025','PFM019','PFM010','IM016','IM039','M024','M047','M044','M021'],
'T1556.004': ['IM001','M003','M018','M028','M004','IM022','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','BFM028','PFM019','PFM010','IM016','IM039','M024','M047','M044','M021'],
'T1556.005': ['IM001','M003','M018','M028','M004','IM022','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1556.006': ['IM001','M003','M018','M028','M004','IM022','IM040','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1556.007': ['IM001','M003','M018','M028','M004','IM022','IM040','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','PFM019','PFM010','IM016','IM039','M024','M047','M044','M021'],
'T1556.008': ['IM001','M003','M018','M028','M004','IM022','IM014','IM012','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1556.009': ['IM001','M003','M018','M028','M004','IM022','IM040','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],

'T1557': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM021','IM032','IM029','IM030','IM034','IM013','BFM025','IM016','IM039','M016','M024','M047','M044','M021'],
'T1557.001': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM021','IM032','IM029','IM030','IM034','IM033','IM013','BFM025','IM016','IM039','M016','M024','M047','M044','M021'], 
'T1557.002': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM021','IM032','BFM009','IM029','IM030','IM034','IM013','BFM025','IM016','IM039','M016','M024','M047','M044','M021'],
'T1557.003': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM021','IM032','IM029','IM030','IM034','IM013','BFM025','IM016','IM039','M016','M024','M047','M044','M021'], 
'T1557.004': ['IM001','M001','BFM016','BFM019','IM014','IM011','IM021','IM032','IM029','IM030','IM034','IM013','BFM025','IM016','IM039','M016','M024','M047','M044','M021'], 

'T1558': ['IM001','M003','M018','M028','M004','IM022','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM028','PFM019','PFM010','IM016','IM039','M024','M047','M044','M021'],
'T1558.001': ['IM001','M003','M018','M028','M004','IM022','BFM016','BFM019','PFM019','PFM010','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'], 
'T1558.002': ['IM001','M003','M018','M028','M004','IM022','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','BFM028','IM016','IM039','M024','M047','M044','M021'], 
'T1558.003': ['IM001','M003','M018','M028','M004','IM022','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'], 
'T1558.004': ['IM001','M003','M018','M028','M004','IM022','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'], 
'T1558.005': ['IM001','M003','M018','M028','M004','IM022','BFM016','BFM019','PFM019','PFM010','IM034','IM033','IM021','IM029','IM030','IM013','BFM028','IM016','IM039','M024','M047','M044','M021'], 

'T1559': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1559.001': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','BFM028','IM016','IM039','M024','M047','M044','M021'], 
'T1559.002': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','IM016','IM039','M024','M047','M044','M021'],  
'T1559.003': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','IM016','IM039','M024','M047','M044','M021'],  

'T1560': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1560.001': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'], 
'T1560.002': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','BFM020','M024','M047','M044','M021'], 
'T1560.003': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','BFM020','M024','M047','M044','M021'], 

'T1561': ['IM001','M001','BFM016','BFM019','BFM037','BFM020','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM041','IM039','M005','M024','M047','M044','M021'],
'T1561.001': ['IM001','M001','BFM016','BFM019','BFM037','BFM020','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM041','IM039','M005','M024','M047','M044','M021'], 
'T1561.002': ['IM001','M001','BFM016','BFM019','BFM037','BFM020','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM041','IM039','M005','M024','M047','M044','M021'], 

'T1562': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM014','IM012','IM029','IM030','IM013','BFM026','BFM028','IM016','IM039','M025','M024','M047','M044','M021'],
'T1562.001': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM014','IM012','IM029','IM030','IM013','BFM026','BFM028','IM016','IM039','M025','M024','M047','M044','M021'],
'T1562.002': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM021','IM029','IM030','IM034','IM013','BFM026','IM016','IM039','M024','M047','M044','M021'],
'T1562.003': ['IM001','M001','BFM016','BFM019','IM032','IM017','IM034','IM033','IM021','IM030','IM013','BFM026','IM016','IM039','M024','M047','M044','M021'],
'T1562.004': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM021','IM032','IM029','IM030','IM034','IM013','BFM025','IM016','IM039','M016','M024','M047','M044','M021'],
'T1562.006': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM021','IM029','IM030','IM034','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1562.007': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM014','IM012','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1562.008': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1562.009': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM028','BFM026','IM016','IM039','M024','M047','M044','M021'],
'T1562.010': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1562.011': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1562.012': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M025','M024','M047','M044','M021'],

'T1563': ['IM001','M003','M018','M028','IM022','BFM016','BFM019','IM017','IM034','IM033','IM021','IM014','IM012','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1563.001': ['IM001','M003','M018','M028','IM022','BFM016','BFM019','IM017','IM034','IM033','IM021','IM014','IM012','IM032','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1563.002': ['IM001','M003','M018','M028','IM022','BFM016','BFM019','IM017','IM034','IM033','IM021','IM014','IM012','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],

'T1564': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','BFM037','IM016','IM039','M024','M047','M044','M021'],
'T1564.001': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','IM016','IM039','M024','M047','M044','M021'],
'T1564.002': ['IM001','M001','BFM016','BFM019','IM022','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','IM016','IM039','M024','M047','M044','M021'],
'T1564.003': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1564.004': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','BFM037','IM016','IM039','M024','M047','M044','M021'],
'T1564.005': ['IM001','M001','BFM016','BFM019','IM032','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','BFM037','IM016','IM039','M024','M047','M044','M021'],
'T1564.006': ['IM001','M001','BFM016','BFM019','IM032','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM020','IM016','IM039','M024','M047','M044','M021'],
'T1564.007': ['IM001','M001','BFM016','BFM019','BFM037','PFM019','PFM010','PFM044','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1564.008': ['IM001','M001','BFM016','BFM019','IM038','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1564.009': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1564.010': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','BFM028','IM016','IM039','M024','M047','M044','M021'],
'T1564.011': ['IM001','M001','BFM016','BFM019','IM032','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1564.012': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM028','IM016','IM039','M024','M047','M044','M021'],
'T1564.013': ['IM001','M001','BFM016','BFM019','IM032','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1564.014': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM021','IM029','IM030','IM013','PFM019','PFM010','PFM044','IM016','IM039','M024','M047','M044','M021'],

'T1565': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1565.001': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','BFM037','IM016','IM039','M024','M047','M044','M021'],
'T1565.002': ['IM001','M001','BFM016','BFM019','BFM009','IM014','IM012','IM021','IM032','IM029','IM030','IM013','BFM025','IM016','IM039','M016','M024','M047','M044','M021'],
'T1565.003': ['IM001','M001','BFM016','BFM019','PFM019','PFM010','PFM044','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],

'T1566': ['IM001','IM038','IM008','IM014','IM012','IM022','IM040','IM039','IM021','IM029','IM030','IM013','IM016','M012','M004','M018','M028','M026','M024','M044','M021'],
'T1566.001': ['IM001','IM038','IM014','IM012','IM017','IM034','IM033','IM022','IM040','IM029','IM030','IM013','BFM026','BFM025','IM016','IM039','M012','M004','M018','M028','M026','M024','M015','M027','M047','M044','M021'],
'T1566.002': ['IM001','IM038','IM008','IM014','IM012','IM022','IM040','IM039','M012','M004','M018','M028','M026','M024','M044','M021'],
'T1566.003': ['IM001','IM038','IM014','IM012','IM022','IM040','IM039','IM021','IM029','IM030','IM013','IM016','M012','M004','M018','M028','M026','M024','M044','M021'],
'T1566.004': ['IM001','IM038','IM014','IM012','IM022','IM040','IM039','IM021','IM029','IM030','IM013','IM016','M012','M004','M018','M028','M026','M024','M044','M021'],

'T1567': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM021','IM029','IM030','IM013','IM032','IM016','IM039','M016','M024','M047','M044','M021'],
'T1567.001': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM014','IM012','IM021','IM029','IM030','IM013','IM032','IM016','IM039','M042','M024','M047','M044','M021'],
'T1567.002': ['IM001','M001','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','IM032','IM039','IM016','M024','M047','M044','M021'],
'T1567.003': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1567.004': ['IM001','M001','BFM016','BFM019','IM038','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],

'T1568': ['IM001','M001','BFM016','BFM019','IM011','IM032','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM039','M016','M024','M047','M044','M021'],
'T1568.001': ['IM001','M001','BFM016','BFM019','IM011','IM014','IM032','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM039','M016','M024','M047','M044','M021'],
'T1568.002': ['IM001','M001','BFM016','BFM019','IM011','IM039','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','M024','M047','M044','M021'],
'T1568.003': ['IM001','M001','BFM016','BFM019','IM011','IM032','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM039','M024','M047','M044','M021'],

'T1569': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M025','M024','M047','M044','M021'],
'T1569.001': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM021','IM029','IM030','IM013','BFM020','BFM025','IM016','IM039','M025','M024','M047','M044','M021'],
'T1569.002': ['IM001','M001','BFM016','BFM019','IM032','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM020','BFM025','IM016','IM039','M025','M024','M047','M044','M021'],
'T1569.003': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM026','BFM028','IM016','IM039','M025','M024','M047','M044','M021'],

'T1573': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M016','M024','M047','M044','M021'],
'T1573.001': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM037','IM016','IM039','M016','M024','M047','M044','M021'],
'T1573.002': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM037','PFM019','PFM010','IM016','IM039','M016','M024','M047','M044','M021'],

'T1574': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM012','IM014','IM029','IM030','IM013','BFM026','BFM028','BFM037','IM016','IM039','M025','M024','M047','M044','M021'],
'T1574.001': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM012','IM014','IM029','IM030','IM013','BFM026','BFM028','BFM037','IM016','IM039','M025','M024','M047','M044','M021'],
'T1574.002': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM012','IM014','IM029','IM030','IM013','BFM026','BFM028','BFM037','IM016','IM039','M025','M024','M047','M044','M021'],
'T1574.004': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM021','IM029','IM030','IM013','BFM020','BFM026','BFM037','IM016','IM039','M025','M024','M047','M044','M021'],
'T1574.005': ['IM001','M001','BFM016','BFM019','IM017','IM013','IM034','IM021','IM029','IM030','BFM026','BFM028','BFM037','IM016','IM039','M025','M024','M047','M044','M021'],
'T1574.006': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM021','IM012','IM014','IM029','IM030','IM013','BFM026','BFM028','BFM037','IM016','IM039','M025','M024','M047','M044','M021'],
'T1574.007': ['IM001','M001','BFM016','BFM019','IM017','IM013','IM034','IM021','IM029','IM030','BFM026','BFM028','IM016','IM039','M025','M024','M047','M044','M021'],
'T1574.008': ['IM001','M001','BFM016','BFM019','IM017','IM013','IM034','IM021','IM029','IM030','BFM026','BFM028','IM016','IM039','M025','M024','M047','M044','M021'],
'T1574.009': ['IM001','M001','BFM016','BFM019','IM017','IM013','IM034','IM021','IM029','IM030','BFM026','BFM028','BFM037','IM016','IM039','M025','M024','M047','M044','M021'],
'T1574.010': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM013','IM021','IM029','IM030','BFM026','BFM028','BFM037','IM016','IM039','M025','M024','M047','M044','M021'],
'T1574.011': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM013','IM021','IM029','IM030','BFM026','BFM028','BFM037','IM016','IM039','M025','M024','M047','M044','M021'],
'T1574.012': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','BFM028','BFM037','IM016','IM039','M025','M024','M047','M044','M021'],
'T1574.013': ['IM001','M001','BFM016','BFM019','PFM019','PFM010','PFM044','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1574.014': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM021','IM029','IM030','IM013','BFM026','BFM037','IM016','IM039','M025','M024','M047','M044','M021'],

'T1578': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M042','M024','M047','M044','M021'],
'T1578.001': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M042','M024','M047','M044','M021'],
'T1578.002': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M042','M024','M047','M044','M021'],
'T1578.003': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M042','M024','M047','M044','M021'],
'T1578.004': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M042','M024','M047','M044','M021'],
'T1578.005': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM034','IM033','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M042','M024','M047','M044','M021'],

'T1583': ['IM001','M001','BFM016','BFM019','IM014','IM021','IM029','IM030','IM039','IM013','IM016','M016','M024','M047','M044','M021'],
'T1583.001': ['IM001','M001','BFM016','BFM019','IM014','IM011','IM021','IM029','IM030','IM039','IM013','IM016','M016','M024','M047','M044','M021'],
'T1583.002': ['IM001','M001','BFM016','BFM019','IM014','IM011','IM021','IM029','IM030','IM039','IM013','IM016','M016','M024','M047','M044','M021'],
'T1583.003': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM032','IM021','IM029','IM030','IM013','IM039','IM016','M016','M024','M047','M044','M021'],
'T1583.004': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM021','IM029','IM030','IM039','IM013','IM016','M016','M024','M047','M044','M021'],
'T1583.005': ['IM001','M001','BFM016','BFM019','IM032','IM014','IM012','IM021','IM029','IM030','IM039','IM016','M039','M024','M047','M044','M021'],
'T1583.006': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM021','IM029','IM030','IM039','IM016','M016','M024','M047','M044','M021'],
'T1583.007': ['IM001','M001','BFM016','BFM019','BFM037','IM014','IM012','IM021','IM029','IM030','IM039','IM016','M025','M024','M047','M044','M021'],
'T1583.008': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM032','IM021','IM029','IM030','IM039','IM016','M016','M024','M047','M044','M021'],

'T1584': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM011','IM021','IM029','IM030','IM039','IM013','IM016','M016','M024','M047','M044','M021'],
'T1584.001': ['IM001','M001','BFM016','BFM019','IM011','IM014','IM021','IM029','IM030','IM039','IM013','IM016','M016','M024','M047','M044','M021'],
'T1584.002': ['IM001','M001','BFM016','BFM019','IM011','IM014','IM012','IM021','IM029','IM030','IM039','IM013','IM016','M016','M024','M047','M044','M021'],
'T1584.003': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM032','IM021','IM029','IM030','IM039','IM013','IM016','M016','M024','M047','M044','M021'],
'T1584.004': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM021','IM029','IM030','IM039','IM013','IM016','M016','M024','M047','M044','M021'],
'T1584.005': ['IM001','M001','BFM016','BFM019','IM032','IM014','IM012','IM021','IM029','IM030','IM039','IM016','M039','M024','M047','M044','M021'],
'T1584.006': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM021','IM029','IM030','IM039','IM016','M016','M024','M047','M044','M021'],
'T1584.007': ['IM001','M001','BFM016','BFM019','BFM037','IM014','IM012','IM021','IM029','IM030','IM039','IM016','M025','M024','M047','M044','M021'],
'T1584.008': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM032','IM021','IM029','IM030','IM039','IM016','M016','M024','M047','M044','M021'],

'T1585': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1585.001': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1585.002': ['IM001','M001','BFM016','BFM019','IM038','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1585.003': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],

'T1586': ['IM001','M003','M018','M028','IM022','BFM016','BFM019','IM038','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1586.001': ['IM001','M003','M018','M028','IM022','IM038','IM039','BFM016','BFM019','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1586.002': ['IM001','M003','M018','M028','IM022','IM038','IM040','BFM016','BFM019','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1586.003': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],

'T1587': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM029','IM030','IM013','BFM037','IM016','IM039','M024','M047','M044','M021'],
'T1587.001': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM029','IM030','IM013','BFM037','IM016','IM039','M024','M047','M044','M021'],
'T1587.002': ['IM001','M001','BFM016','BFM019','BFM037','IM014','IM012','IM029','IM030','IM013','IM016','IM039','M025','M024','M047','M044','M021'],
'T1587.003': ['IM001','M001','BFM016','BFM019','BFM037','IM014','IM012','IM029','IM030','IM013','IM016','IM039','M025','M024','M047','M044','M021'],
'T1587.004': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM029','IM030','IM039','IM013','IM016','M024','M047','M044','M021'],

'T1588': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM029','IM030','IM039','IM013','IM016','M024','M047','M044','M021'],
'T1588.001': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM029','IM030','IM039','IM013','BFM037','IM016','M024','M047','M044','M021'],
'T1588.002': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM029','IM030','IM039','IM013','IM016','M024','M047','M044','M021'],
'T1588.003': ['IM001','M001','BFM016','BFM019','BFM037','IM014','IM012','IM029','IM030','IM039','IM013','IM016','M025','M024','M047','M044','M021'],
'T1588.004': ['IM001','M001','BFM016','BFM019','BFM037','IM014','IM012','IM029','IM030','IM039','IM013','IM016','M025','M024','M047','M044','M021'],
'T1588.005': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM029','IM030','IM039','IM013','IM016','M024','M047','M044','M021'],
'T1588.006': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM021','IM029','IM030','IM039','IM013','IM016','M016','M024','M047','M044','M021'],
'T1588.007': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM029','IM030','IM039','IM013','BFM037','IM016','M024','M047','M044','M021'],

'T1589': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1589.001': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1589.002': ['IM001','M001','BFM016','BFM019','IM039','IM038','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1589.003': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],

'T1590': ['IM001','M001','BFM016','BFM019','IM011','IM014','IM032','IM039','IM029','IM030','IM013','IM016','M016','M024','M047','M044','M021'],
'T1590.001': ['IM001','M001','BFM016','BFM019','IM011','IM014','IM039','IM029','IM030','IM013','IM016','M016','M024','M047','M044','M021'],
'T1590.002': ['IM001','M001','BFM016','BFM019','IM011','IM014','IM039','IM029','IM030','IM013','IM016','M016','M024','M047','M044','M021'],
'T1590.003': ['IM001','M001','BFM016','BFM019','IM011','IM032','IM039','IM029','IM030','IM013','IM016','M016','M024','M047','M044','M021'],
'T1590.004': ['IM001','M001','BFM016','BFM019','IM011','IM014','IM032','IM039','IM029','IM030','IM013','IM016','M016','M024','M047','M044','M021'],
'T1590.005': ['IM001','M001','BFM016','BFM019','IM011','IM014','IM032','IM039','IM029','IM030','IM013','IM016','M016','M024','M047','M044','M021'],
'T1590.006': ['IM001','M001','BFM016','BFM019','IM011','IM014','IM032','IM039','IM029','IM030','IM013','IM016','M016','M024','M047','M044','M021'],

'T1591': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1591.001': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1591.002': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1591.003': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1591.004': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],

'T1592': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1592.001': ['IM001','M001','BFM016','BFM019','IM032','IM029','IM030','IM013','BFM020','IM016','IM039','M024','M047','M044','M021'],
'T1592.002': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM029','IM030','IM013','BFM026','BFM037','IM016','IM039','M024','M047','M044','M021'],
'T1592.003': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM029','IM030','IM013','PFM019','PFM010','IM016','IM039','M024','M047','M044','M021'],
'T1592.004': ['IM001','M001','BFM016','BFM019','IM013','IM017','IM034','IM033','IM029','IM030','BFM020','IM016','IM039','M024','M047','M044','M021'],

'T1593': ['IM001','M001','BFM016','BFM019','IM011','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1593.001': ['IM001','M001','BFM016','BFM019','IM011','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1593.002': ['IM001','M001','BFM016','BFM019','BFM037','IM011','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1593.003': ['IM001','M001','BFM016','BFM019','IM011','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],

'T1595': ['IM001','M001','BFM016','BFM019','IM014','IM032','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1595.001': ['IM001','M001','BFM016','BFM019','IM014','IM032','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1595.002': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM014','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1595.003': ['IM001','M001','BFM016','BFM019','IM014','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],

'T1596': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1596.001': ['IM001','M001','BFM016','BFM019','IM039','IM038','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1596.002': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1596.003': ['IM001','M001','BFM016','BFM019','IM039','IM034','IM033','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1596.004': ['IM001','M001','BFM016','BFM019','IM039','IM014','IM012','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1596.005': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],

'T1597': ['IM001','M001','BFM016','BFM019','IM039','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1597.001': ['IM001','M001','BFM016','BFM019','IM039','IM038','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],
'T1597.002': ['IM001','M001','BFM016','BFM019','IM039','IM017','IM034','IM033','IM029','IM030','IM013','IM016','M024','M047','M044','M021'],

'T1598': ['IM001','M001','BFM016','BFM019','IM038','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1598.001': ['IM001','M001','BFM016','BFM019','IM038','IM017','IM034','IM033','IM021','IM012','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1598.002': ['IM001','M001','BFM016','BFM019','IM038','IM017','IM034','IM033','IM021','IM014','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1598.003': ['IM001','M001','BFM016','BFM019','IM038','IM017','IM034','IM033','IM021','IM040','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1598.004': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM038','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],

'T1599': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM032','IM021','IM029','IM030','IM013','BFM009','IM016','IM039','M016','M024','M047','M044','M021'],
'T1599.001': ['IM001','M001','BFM016','BFM019','IM014','IM012','IM032','IM021','IM029','IM030','IM013','BFM009','IM016','IM039','M016','M024','M047','M044','M021'],

'T1600': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1600.001': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM029','IM030','IM013','IM016','IM039','M025','M024','M047','M044','M021'],
'T1600.002': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM029','IM030','IM013','IM016','IM039','M025','M024','M047','M044','M021'],

'T1601': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM029','IM030','IM013','PFM019','PFM010','IM016','IM039','M024','M047','M044','M021'],
'T1601.001': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM029','IM030','IM013','PFM019','PFM010','IM016','IM039','M024','M047','M044','M021'],
'T1601.002': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM029','IM030','IM013','BFM026','PFM019','PFM010','IM016','IM039','M024','M047','M044','M021'],

'T1602': ['IM001','M001','BFM016','BFM019','IM032','IM014','IM012','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1602.001': ['IM001','M001','BFM016','BFM019','IM032','IM014','IM012','IM021','IM029','IM030','IM013','BFM025','IM016','IM039','M024','M047','M044','M021'],
'T1602.002': ['IM001','M001','BFM016','BFM019','IM032','IM014','IM012','IM021','IM029','IM030','IM013','BFM025','BFM020','IM016','IM039','M024','M047','M044','M021'],

'T1606': ['IM001','M003','M018','M028','IM022','BFM016','BFM019','IM038','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1606.001': ['IM001','M003','M018','M028','IM022','IM038','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1606.002': ['IM001','M003','M018','M028','IM022','IM040','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],

'T1608': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM012','IM014','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1608.001': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM012','IM014','IM029','IM030','IM013','BFM037','IM016','IM039','M024','M047','M044','M021'],
'T1608.002': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM012','IM014','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1608.003': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM012','IM014','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1608.004': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM012','IM014','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1608.005': ['IM001','M001','BFM016','BFM019','BFM037','IM014','IM012','IM029','IM030','IM013','IM016','IM039','M025','M024','M047','M044','M021'],
'T1608.006': ['IM001','M001','BFM016','BFM019','BFM037','IM017','IM034','IM033','IM032','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],

'T1614': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
'T1614.001': ['IM001','M001','BFM016','BFM019','IM017','IM034','IM033','IM021','IM029','IM030','IM013','IM016','IM039','M024','M047','M044','M021'],
};


// ---------- 3) Initialisierung & Konfigurations-Hygiene ----------
/**
 * Bereinigt das `tacticToActionMap` beim Start der Anwendung.
 * Maßnahmen, die mit '//nur durch Logik ins Mapping' markiert sind, werden entfernt,
 * da sie ausschließlich dynamisch durch die Anwendungslogik hinzugefügt werden sollen.
 * Dies verhindert, dass sie fälschlicherweise direkt aus der Map geladen werden.
 */
function cleanLogicOnlyMeasuresFromMap() {
  const LOGIC_ONLY_MARKER = '//nur durch Logik ins Mapping';
  
  // 1. Finde alle Maßnahmen, die als "nur durch Logik" markiert sind.
  const logicOnlyMeasures = new Set<string>();
  for (const [id, text] of Object.entries(measures)) {
    if (text.includes(LOGIC_ONLY_MARKER)) {
      logicOnlyMeasures.add(id);
    }
  }

  // 2. Durchlaufe die Map und entferne diese Maßnahmen.
  for (const tactic in tacticToActionMap) {
    const originalActions = tacticToActionMap[tactic];
    const cleanedActions = originalActions.filter(id => !logicOnlyMeasures.has(id));

    if (originalActions.length !== cleanedActions.length) {
      console.warn(`[Config Cleanup] Removed logic-only measures from tactic '${tactic}'. Found: ${originalActions.filter(id => logicOnlyMeasures.has(id)).join(', ')}`);
      tacticToActionMap[tactic] = cleanedActions;
    }
  }
}

// ---------- 4) DOM-Selektoren & Konstanten ----------
const actionsDisplay = document.getElementById('actions-display') as HTMLDivElement | null;
const tacticInput    = document.getElementById('text-input') as HTMLInputElement | null;

const itForm         = document.getElementById('it-dependencies-form') as HTMLFormElement | null;
const itStatus       = document.getElementById('it-status') as HTMLParagraphElement | null;
const reimageSelect  = document.getElementById('reimage-select') as HTMLSelectElement | null;
const forensicsSelect= document.getElementById('forensics-select') as HTMLSelectElement | null;
const irCapacitySelect = document.getElementById('ir-capacity-select') as HTMLSelectElement | null;

const complianceForm    = document.getElementById('compliance-form') as HTMLFormElement | null;
const complianceStatus  = document.getElementById('compliance-status') as HTMLParagraphElement | null;

// Konstanten für die Werte der Select-Optionen
const REIMAGE_WITHOUT_PROBLEMS = 'reimage';   // Wert für "Reimaging possible without problems"
const REIMAGE_ONLY_EMERGENCY   = 'noreimage'; // Wert für "Reimaging only in emergencies"

// Schlüssel für den Local Storage
const STORAGE_IT = 'settings.it';
const STORAGE_COMPLIANCE = 'settings.compliance';

// ---------- 5) Typ-Definitionen & Local Storage Helper ----------
type ItState = { reimage: string; forensics?: string; irCapacity?: string };
type ComplianceState = { regulatory: string[]; voluntary: string[] };

function saveIt(state: ItState) {
  localStorage.setItem(STORAGE_IT, JSON.stringify(state));
}
function loadIt(): ItState | null {
  const raw = localStorage.getItem(STORAGE_IT);
  return raw ? JSON.parse(raw) : null;
}
function saveCompliance(state: ComplianceState) {
  localStorage.setItem(STORAGE_COMPLIANCE, JSON.stringify(state));
}
function loadCompliance(): ComplianceState | null {
  const raw = localStorage.getItem(STORAGE_COMPLIANCE);
  return raw ? JSON.parse(raw) : null;
}
/**
 * Liest die Werte aller aktivierten Checkboxen aus einer NodeList aus.
 * @param nodes Eine NodeList von HTMLInputElement (Checkboxes).
 * @returns Ein Array der `value`-Attribute der aktivierten Checkboxen.
 */
function getCheckedValues(nodes: NodeListOf<HTMLInputElement>): string[] {
  const vals: string[] = [];
  nodes.forEach(cb => { if (cb.checked) vals.push(cb.value); });
  return vals;
}
/**
 * Setzt den `checked`-Status von Checkboxen basierend auf einem Array von Werten.
 * @param nodes Eine NodeList von HTMLInputElement (Checkboxes).
 * @param values Ein Array von Werten, die den `checked`-Status auf `true` setzen sollen.
 */
function setCheckedValues(nodes: NodeListOf<HTMLInputElement>, values: string[]) {
  const set = new Set(values);
  nodes.forEach(cb => { cb.checked = set.has(cb.value); });
}
function markInvalidStyles() {
  if (reimageSelect)   reimageSelect.classList.toggle('invalid', !reimageSelect.value);
  if (forensicsSelect) forensicsSelect.classList.toggle('invalid', !forensicsSelect.value);
  if (irCapacitySelect) irCapacitySelect.classList.toggle('invalid', !irCapacitySelect.value);
}

/**
 * IIFE (Immediately Invoked Function Expression) zur Hydration der Anwendung beim Laden.
 * - Bereinigt die Konfigurations-Map.
 * - Lädt Einstellungen aus dem Local Storage und wendet sie auf die Formulare an.
 * - Setzt das Forensik-Level basierend auf den geladenen Compliance-Einstellungen.
 * - Führt eine erste Aktualisierung der Maßnahmen durch, falls bereits eine Taktik im Input-Feld steht.
 * - Initialisiert den Timer für die "Alert Start Time".
 */
(function hydrate() {
  cleanLogicOnlyMeasuresFromMap();

  const it = loadIt();
  if (it) {
    if (reimageSelect)   reimageSelect.value   = it.reimage ?? '';
    if (forensicsSelect) forensicsSelect.value = it.forensics ?? '';
    if (irCapacitySelect) irCapacitySelect.value = it.irCapacity ?? '';
  }
  const ctx = loadCompliance();
  if (ctx && complianceForm) {
    const regulatoryChecks = complianceForm.querySelectorAll<HTMLInputElement>('input[name="regulatory"]');
    const voluntaryChecks  = complianceForm.querySelectorAll<HTMLInputElement>('input[name="voluntary"]');
    setCheckedValues(regulatoryChecks, ctx.regulatory ?? []);
    setCheckedValues(voluntaryChecks,  ctx.voluntary  ?? []);
  }
  setForensicsLevelFromCompliance();

  markInvalidStyles();

  if (tacticInput && tacticInput.value.trim()) {
    updateActionsDisplay(tacticInput.value.trim());
  }
  initAlertTimer();
})();

/**
 * Bestimmt das erforderliche Forensik-Level basierend auf den gespeicherten Compliance-Einstellungen.
 * Die höchste Anforderung gewinnt immer.
 * @returns 'profforensics', 'basicforensics' oder 'noforensics'.
 */
function getForensicsLevel(): string {
  const compliance = loadCompliance();
  if (!compliance) return 'noforensics';

  const allSelectedContexts = new Set([
    ...(compliance.regulatory ?? []),
    ...(compliance.voluntary ?? [])
  ]);

  // Hohe Forensikanforderungen
  if (allSelectedContexts.has('BAIT / VAIT / KAIT / ZAIT') || 
      allSelectedContexts.has('BSIG & German IT Security Act 2.0') || 
      allSelectedContexts.has('DORA') || 
      allSelectedContexts.has('EnergieKRITIS / EnWG §11') || 
      allSelectedContexts.has('gematik')) {
    return 'profforensics';
  }

  // Mittlere Forensikanforderungen
  if (allSelectedContexts.has('EU-GDPR & BDSG') || 
      allSelectedContexts.has('NIS-2') || 
      allSelectedContexts.has('TKG') || 
      allSelectedContexts.has('B3S') || 
      allSelectedContexts.has('C5')) {
    return 'basicforensics';
  }

  // Niedrige oder keine spezifischen Forensikanforderungen
  return 'noforensics';
}

/**
 * Setzt den Wert des Forensik-Dropdowns basierend auf den ermittelten Compliance-Anforderungen.
 */
function setForensicsLevelFromCompliance() {
  const forensicsLevel = getForensicsLevel();
  if (forensicsSelect) {
    forensicsSelect.value = forensicsLevel;
    markInvalidStyles();
  }
}

function initCollapsibleCards() {
  const cardContainers = document.querySelectorAll<HTMLElement>('#it-dependencies-container, #compliance-container, #forensic-note-container');

  cardContainers.forEach(container => {
    const header = container.querySelector<HTMLElement>('.card-header');
    const button = container.querySelector<HTMLButtonElement>('.toggle-btn');
    const content = container.querySelector<HTMLElement>('.card-content');
    const storageKey = `ui.collapsed.${container.id}`;

    if (!header || !button || !content) return;

    // Zustand aus dem Local Storage wiederherstellen
    const isCollapsed = localStorage.getItem(storageKey) === 'true';
    if (isCollapsed) {
      container.classList.add('collapsed');
      button.setAttribute('aria-expanded', 'false');
    }

    header.addEventListener('click', () => {
      const currentlyCollapsed = container.classList.toggle('collapsed');
      button.setAttribute('aria-expanded', String(!currentlyCollapsed));
      localStorage.setItem(storageKey, String(currentlyCollapsed));
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  createForensicNoteSection();
  initCollapsibleCards();
});

/**
 * Erstellt eine eigene, aufklappbare Karte für die forensischen Hinweise.
 */
function createForensicNoteSection() {
  const complianceContainer = document.getElementById('compliance-container');
  if (!complianceContainer) return;

  const container = document.createElement('div');
  container.id = 'forensic-note-container';
  container.className = 'card-section';
  container.innerHTML = `
    <div class="card-header">
      <h3>Note on forensic analysis</h3>
      <button class="toggle-btn" aria-expanded="true">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
      </button>
    </div>
    <div class="card-content">
      <ul style="text-align: left; margin: 0; padding-left: 20px; color: #a0aec0;">
        <li>No AV scan or automatic cleanup before data backup</li>
        <li>No direct login on compromised systems</li>
        <li>No repair or recovery functions (e.g., SFC, chkdsk)</li>
        <li>Do not delete, move, or overwrite files</li>
      </ul>
    </div>
  `;

  complianceContainer.insertAdjacentElement('afterend', container);
}

// ---------- 6) Event-Handler für Formulare ----------
itForm?.addEventListener('submit', (e) => {
  e.preventDefault();

  // HTML5-Validierung plus manuelle Prüfung, ob alle Felder einen Wert haben
  if (!itForm.checkValidity() || !(reimageSelect?.value && forensicsSelect?.value && irCapacitySelect?.value)) {
    itForm.reportValidity?.();
    markInvalidStyles();
    if (actionsDisplay) {
      actionsDisplay.innerHTML = '<p class="error">Please set all IT Dependencies (Reimage, Forensics, Capacities).</p>';
    }
    return;
  }

  const state: ItState = {
    reimage: reimageSelect?.value ?? '',
    forensics: forensicsSelect?.value ?? '',
    irCapacity: irCapacitySelect?.value ?? '',
  };
  saveIt(state);
  window.dispatchEvent(new CustomEvent('settings:changed', { detail: { it: state } }));

  if (itStatus) { itStatus.textContent = 'Saved ✔'; setTimeout(() => itStatus.textContent = '', 1200); }

  if (tacticInput) updateActionsDisplay(tacticInput.value.trim());
});

// Live-Validierung der IT-Abhängigkeiten bei jeder Änderung
reimageSelect?.addEventListener('change', () => { markInvalidStyles(); if (tacticInput) updateActionsDisplay(tacticInput.value.trim()); });
forensicsSelect?.addEventListener('change', () => { markInvalidStyles(); if (tacticInput) updateActionsDisplay(tacticInput.value.trim()); });
irCapacitySelect?.addEventListener('change', () => { markInvalidStyles(); if (tacticInput) updateActionsDisplay(tacticInput.value.trim()); });

complianceForm?.addEventListener('submit', (e) => {
  e.preventDefault();

  // Logik zur Kopplung von B3S und BSIG: Wenn B3S ausgewählt ist,
  // wird BSIG automatisch ebenfalls ausgewählt.
  const b3sCheckbox = document.getElementById('b3s') as HTMLInputElement | null;
  const bsigCheckbox = document.getElementById('bsig') as HTMLInputElement | null;
  if (b3sCheckbox?.checked && bsigCheckbox) {
    bsigCheckbox.checked = true;
  }

  const regulatoryChecks = complianceForm.querySelectorAll<HTMLInputElement>('input[name="regulatory"]');
  const voluntaryChecks  = complianceForm.querySelectorAll<HTMLInputElement>('input[name="voluntary"]');
  const state: ComplianceState = {
    regulatory: getCheckedValues(regulatoryChecks),
    voluntary:  getCheckedValues(voluntaryChecks),
  };
  saveCompliance(state);
  window.dispatchEvent(new CustomEvent('settings:changed', { detail: { compliance: state } }));
  if (complianceStatus) { complianceStatus.textContent = 'Saved ✔'; setTimeout(() => complianceStatus.textContent = '', 1200); }
  if (tacticInput) {
    updateActionsDisplay(tacticInput.value.trim());
    updateReportingDeadlines();
    setForensicsLevelFromCompliance();
  }
});

// Event-Handler für das Haupt-Eingabeformular (Taktik)
const mitreForm = document.getElementById('input-form') as HTMLFormElement | null;
mitreForm?.addEventListener('submit', (e) => {
  e.preventDefault();
  if (tacticInput) {
    const tacticId = tacticInput.value.trim().split(' ')[0];
    updateActionsDisplay(tacticId);
  }
});

// Event Listener für das Taktik-Eingabefeld, um bei Auswahl aus der Datalist
// den vollen Namen anzuzeigen und die Maßnahmenliste direkt zu aktualisieren.
tacticInput?.addEventListener('input', () => {
  if (!tacticInput) return;

  const tacticValue = tacticInput.value;
  const dataList = document.getElementById('mitre-tactics-list');
  const option = Array.from(dataList?.getElementsByTagName('option') ?? []).find(opt => opt.value === tacticValue);

  if (option) {
    // Setze den vollen Namen in das Input-Feld und aktualisiere die Anzeige
    tacticInput.value = option.textContent || tacticValue;
    updateActionsDisplay(tacticValue); // Übergibt den Taktik-Code (z.B. 'T1059')
  } else if (tacticValue.includes(' - ')) {
    // Aktualisiere auch, wenn der Benutzer manuell tippt und der volle Name bereits im Feld steht
    const tacticId = tacticValue.split(' ')[0];
    updateActionsDisplay(tacticId);
  }
});

// ---------- 7) Anzeige-Logik ----------
function isGdprSelected(): boolean {
  try {
    const compliance = loadCompliance?.();
    return !!compliance && Array.isArray(compliance.regulatory) && compliance.regulatory.includes('EU-GDPR & BDSG');
  } catch { return false; }
}

/**
 * Hauptfunktion zur Aktualisierung der Maßnahmenanzeige.
 * @param tacticId Die ID der ausgewählten Taktik (z.B. 'T1059' oder 'WannaCry').
 */
function updateActionsDisplay(tacticId: string) {
  if (!actionsDisplay) return;

  const table = document.querySelector('.actions-table') as HTMLTableElement | null;
  const tableBody = table?.querySelector('tbody') as HTMLTableSectionElement | null;

  if (!actionsDisplay.querySelector('.actions-header')) { // Header nur einfügen, falls nicht vorhanden
    actionsDisplay.innerHTML = `
      <div class="actions-header">
        <h3>Recommended Actions</h3>
        <div class="copy-controls">
          <button id="copy-actions-btn" class="copy-btn" title="Copy all actions to clipboard">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-copy"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2v2"/></svg>
          </button>
          <span id="actions-copy-feedback" class="copy-feedback"></span>
        </div>
      </div>
    `;
  }
  const tableHead = table?.querySelector('thead');
  if (tableHead) {
    tableHead.innerHTML = `
      <tr>
        <th>Timestamp</th><th>Recommended Action</th><th>Interaction / Result</th>
      </tr>
    `;
  }

  if (!tableBody) return;
  tableBody.innerHTML = ''; // Bestehenden Tabelleninhalt leeren

  // Event Listener für den Kopier-Button hinzufügen
  const copyBtn = actionsDisplay.querySelector('#copy-actions-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      copyTableWithStyles(table, 'actions-copy-feedback');
    });
  }

  // Vorbedingung: Alle IT-Abhängigkeiten müssen gesetzt sein
  if (!(reimageSelect?.value && forensicsSelect?.value && irCapacitySelect?.value)) {
    tableBody.innerHTML = '<tr><td colspan="3"><p class="error">Please set all IT Dependencies (Reimage, Forensics, Capacities).</p></td></tr>';
    return;
  }

  // Maßnahmen für die Taktik ermitteln (mit Fallback auf die Haupttaktik bei Sub-Techniques)
  let actionIds = tacticToActionMap[tacticId];
  if (!actionIds && tacticId.includes('.')) {
    actionIds = tacticToActionMap[tacticId.split('.')[0]];
  }

  if (!actionIds || !actionIds.length) {
    tableBody.innerHTML = '<tr><td colspan="3"><p>No recommended actions found for this tactic.</p></td></tr>';
    return;
  }

  let current = [...actionIds];

  // Merken, ob ursprünglich Professional Forensic Measures (PFM) vorhanden waren
  const hasPfmMeasuresInitially = actionIds.some(id => id.startsWith('PFM'));

  // Forensik-Level aus Compliance-Einstellungen ermitteln (Dropdown als Fallback)
  const forensicsKnowHow = getForensicsLevel() || forensicsSelect?.value;

  if (forensicsKnowHow === 'basicforensics') {
    current = current.filter(id => !id.startsWith('PFM')); // PFM-Maßnahmen entfernen
  } else if (forensicsKnowHow === 'noforensics') {
    current = current.filter(id => !id.startsWith('PFM') && !id.startsWith('BFM')); // PFM- und BFM-Maßnahmen entfernen
  }

  // TODO: Diese Logik muss noch implementiert werden, um Ausnahmen für das Reimaging zu definieren.
  const isReimageException = false; // Temporär deaktiviert, um die Logik zu korrigieren.

  // Sonderregel: Wenn Reimaging nur im Notfall erlaubt ist und M005 (Reimage Client)
  // vorgeschlagen wird, werden stattdessen alternative Bereinigungsmaßnahmen hinzugefügt.
  if (current.includes('M005') && reimageSelect?.value === REIMAGE_ONLY_EMERGENCY) {
    if (isReimageException) {
      // NEU: Bei Ausnahme-Taktiken, füge M022 (backup) vor M005 (reimage) ein.
      const m005Index = current.indexOf('M005');
      if (m005Index > -1 && !current.includes('M022')) {
        current.splice(m005Index, 0, 'M022');
      }
    } else {
    current = current.filter(id => id !== 'M005');
    ['M025','M047','M010'].forEach(add => { if (!current.includes(add)) current.push(add); });
  }
  }


  // Sonderregel für begrenzte IR-Kapazitäten: Wenn "important_only" ausgewählt ist,
  // werden nur die Maßnahmen aus der Whitelist angezeigt.
  if (irCapacitySelect?.value === 'important_only') {
    const whitelist = new Set([
        'IM001', 'IM012', 'IM017', 'IM029', 'IM033', 'IM021', 
        'BFM016', 'BFM019', 'BFM028', 'BFM025', 
        'M001', 'M002', 'M003', 'M007', 'M010', 'M017', 'M026', 'M045', 'M009', 'M024', 
        'M030', 'M033', 'M034', 'M035', 'M036', 'M043', 'M046', 'M047', 'M048', 
        'M050', 'M051', 'M052', 'M053', 'M054', 'M055', 'M022'
    ]);
    current = current.filter(id => whitelist.has(id));
  }

  // Zustand für die Antworten auf "Anything suspicious?"-Prompts
  const suspiciousAnswers = new Set<string>();

  // NEUE LOGIK für M020: "update security patches if relevant"
  // M020 wird nur hinzugefügt, wenn alle folgenden Bedingungen erfüllt sind:
  // 1. Ein Reimage, Server-Rebuild oder Backup-Restore hat stattgefunden.
  const reimageCondition = current.some(id => ['M005', 'M048', 'M043'].includes(id));
  
  // 2. Der Angriff war nicht primär E-Mail-basiert.
  const emailCondition = !current.some(id => ['M006', 'M012'].includes(id));
  
  // 3. Es gibt Anzeichen, dass eine Schwachstelle relevant war.
  // Diese Prüfung wird jetzt innerhalb der render-Schleife durchgeführt, da sie von den Benutzerantworten abhängt.
  const addM020IfNeeded = () => {
    const vulnerabilityCondition = (current.includes('IM034') && suspiciousAnswers.has('IM034')) ||
      (current.includes('IM032') && suspiciousAnswers.has('IM032')) ||
      // Da IM017 keine Abfrage mehr hat, wird die Bedingung so angepasst, dass sie bei Vorhandensein von IM017 und IM039 als erfüllt gilt.
      (current.includes('IM017') && current.includes('IM039'));
  
    if (reimageCondition && emailCondition && vulnerabilityCondition && !current.includes('M020')) {
      const lastReimageIndex = Math.max(
        current.lastIndexOf('M005'),
        current.lastIndexOf('M048'),
        current.lastIndexOf('M043')
      );
  
      if (lastReimageIndex > -1) {
        current.splice(lastReimageIndex + 1, 0, 'M020');
      }
    }
  }

  // Sicherstellen, dass M024 ("Identify additional compromised hosts...") immer vor
  // IM033 ("hunt for additional infected endpoints...") kommt, falls beide vorhanden sind.
  const im033Index = current.indexOf('IM033');
  if (im033Index > -1) {
    const m024Index = current.indexOf('M024');
    if (m024Index === -1) {
      current.splice(im033Index, 0, 'M024');
    }
  }

  const phasesContainer = document.getElementById('phases-container') as HTMLDivElement;
  renderMeasuresStepwise(current, hasPfmMeasuresInitially, tableBody, phasesContainer, suspiciousAnswers, addM020IfNeeded);
}

// Präfixe, die aus den zusammengefassten Maßnahmenbeschreibungen entfernt werden.
const ISO_PREFIX = /^Inform the company Information Security Officer( and Data Protection Officer)? -> /;
const DPO_PREFIX = /^Inform the company Data Protection Officer -> /;

// Helper function to render grouped measures with a header and sub-items
function renderGroupedMeasures(
    measures: { id: string; text: string }[],
    headerText: string,
    prefixToRemove: RegExp,
    targetTableBody: HTMLTableSectionElement,
    renderedMeasuresSet: Set<string>,
    measureCounter: number
) {
    if (measures.length > 0) {
        const headerRow = targetTableBody.insertRow();
        
        // Zelle 1 für den Header-Timestamp
        const headerTsCell = headerRow.insertCell();
        headerTsCell.style.width = '185px';
        const headerTsButton = document.createElement('button');
        headerTsButton.className = 'btn-secondary';
        headerTsButton.title = 'Set current time';
        headerTsCell.appendChild(headerTsButton);

        const headerTsInput = document.createElement('input');
        headerTsInput.type = 'text';
        headerTsInput.className = 'timestamp-input';
        headerTsInput.placeholder = 'dd.mm.yyyy hh:mm:ss';
        headerTsCell.appendChild(headerTsInput);

        // Zelle 2 für den Header-Text
        const headerCell = headerRow.insertCell();
        const headerTextSpan = document.createElement('span');
        headerTextSpan.className = 'measure-text';
        headerTextSpan.innerHTML = `<i style="color: #6cb2eb; padding-top: 10px; display: inline-block;">${measureCounter}. ${headerText}</i>`;
        headerCell.appendChild(headerTextSpan);
        
        // Zelle 3 für Interaktion (bleibt beim Header leer)
        headerRow.insertCell();

        // Event Listener für den Header-Timestamp
        updateTimestampButtonIcon(headerTsButton, headerTsInput, headerTextSpan);
        measureCounter++;
        headerTsButton.addEventListener('click', () => {
            const now = new Date();
            const timestamp = `${pad(now.getDate())}.${pad(now.getMonth() + 1)}.${now.getFullYear()} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
            const innerTextElement = headerTextSpan.querySelector('i');
            if (!innerTextElement) return;
            
            if (headerTsInput.value && innerTextElement.style.textDecoration !== 'line-through') {
                // Wenn ein Wert vorhanden und nicht durchgestrichen ist -> durchstreichen
                headerTsInput.value = '';
                innerTextElement.style.textDecoration = 'line-through';
            } else {
                // Otherwise (it's struck through, or it's empty), set the timestamp and remove strike
                headerTsInput.value = timestamp;
                innerTextElement.style.textDecoration = '';
            }
            updateTimestampButtonIcon(headerTsButton, headerTsInput, innerTextElement);
        });

        measures.forEach(({ id, text }) => {
            const cleanedText = text.replace(prefixToRemove, '');
            const subRow = targetTableBody.insertRow();
            subRow.setAttribute('data-measure-id', id);
            renderedMeasuresSet.add(id);

            // Zelle 1: Leer, da der Header den Timestamp hat
            subRow.insertCell(); 

            // Zelle 2: Maßnahme
            const measureCell = subRow.insertCell();
            measureCell.innerHTML = `<span style="padding-left: 20px; display: block;"><i style="color: #6cb2eb;">- ${cleanedText} (${id})</i></span>`;

            // Zelle 3: Leer
            subRow.insertCell();
        });
    }
    return measureCounter;
}

const pad = (n: number) => String(n).padStart(2, '0');

// Hilfsfunktion zur Aktualisierung des Button-Icons (Uhr vs. durchgestrichen)
const updateTimestampButtonIcon = (tsButton: HTMLButtonElement, tsInput: HTMLInputElement, textSpan: HTMLSpanElement) => {
    const timestampIconSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>`;
    const strikethroughIconSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="8" y1="12" x2="16" y2="12"/></svg>`;

    if (tsInput.value && textSpan.style.textDecoration !== 'line-through') {
        // Timestamp is set, next click will strikethrough
        tsButton.innerHTML = strikethroughIconSvg;
    } else {
        // Text is struck through, or neither is set, next click will set timestamp
        tsButton.innerHTML = timestampIconSvg;
    }
}

/**
 * Rendert die Maßnahmen schrittweise und interaktiv in der Tabelle.
 * Diese Funktion ist das Herzstück der dynamischen Anzeige und enthält die Logik für Abfragen an den Benutzer.
 * @param list Array der anzuzeigenden Maßnahmen-IDs.
 * @param hasPfmMeasuresInitially Flag, ob ursprünglich PFM-Maßnahmen vorhanden waren.
 * @param targetTableBody Das `<tbody>`-Element der Zieltabelle.
 * @param phasesContainer Der Container für die vertikalen Phasenbalken.
 * @param suspiciousAnswers Ein Set zur Verfolgung von "yes/not sure"-Antworten.
 * @param addM020IfNeeded Callback-Funktion zum Hinzufügen von M020.
 */
function renderMeasuresStepwise(
  list: string[], 
  hasPfmMeasuresInitially: boolean, 
  targetTableBody: HTMLTableSectionElement, 
  phasesContainer: HTMLDivElement,
  suspiciousAnswers: Set<string>,
  addM020IfNeeded: () => void
) {
  const pad = (n: number) => String(n).padStart(2, '0');

  let measureCounter = 1;
  let notSureWasSelected = false; 
  let bfm001Added = false; // Flag, um doppeltes Hinzufügen von BFM001 zu verhindern
  const renderedMeasures = new Set<string>(); // Verfolgt alle bereits gerenderten oder zur Renderung vorgesehenen Maßnahmen
  const suspiciousNoAnswers = new Set<string>(); // NEU: Verfolgt "no"-Antworten für bestimmte Prompts

  const addMeasureToListIfNeeded = (measureId: string, afterIndex: number) => {
    // Füge die Maßnahme nur hinzu, wenn sie weder bereits gerendert wurde noch in der restlichen Liste vorkommt.
    if (!renderedMeasures.has(measureId)) {
      const remainingList = list.slice(afterIndex + 1);
      if (!remainingList.includes(measureId)) {
        list.splice(afterIndex + 1, 0, measureId);
        return true; // Signalisiert, dass etwas hinzugefügt wurde.
      }
    }
    return false; // Nichts wurde hinzugefügt.
  };




  const addM009IfNeeded = () => {
    if (!renderedMeasures.has('M009')) {
      const measureText = allMeasures['M009'];
      if (measureText) {
        const row = targetTableBody.insertRow();
        row.setAttribute('data-measure-id', 'M009');

        // Zelle 1: Timestamp
        const cell1 = row.insertCell();
        const tsButton = document.createElement('button');
        tsButton.className = 'btn-secondary';
        tsButton.title = 'Set current time';
        tsButton.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>`;
        cell1.appendChild(tsButton);
        const tsInput = document.createElement('input');
        tsInput.type = 'text';
        tsInput.className = 'timestamp-input';
        tsInput.placeholder = 'dd.mm.yyyy hh:mm:ss';
        cell1.appendChild(tsInput);

        // Zelle 2: Maßnahme
        const cell2 = row.insertCell();
        const textSpan = document.createElement('span');
        textSpan.className = 'measure-text';
        textSpan.innerHTML = `<i style="color: #6cb2eb;">${measureCounter}. ${measureText} (M009)</i>`;
        measureCounter++;
        cell2.appendChild(textSpan);

        // Initialen Icon-Status setzen
        updateTimestampButtonIcon(tsButton, tsInput, textSpan);

        // Zelle 3 bleibt leer
        row.insertCell(); // Zelle 3

        tsButton.addEventListener('click', () => {
            const now = new Date();
            const timestamp = `${pad(now.getDate())}.${pad(now.getMonth() + 1)}.${now.getFullYear()} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;

            if (textSpan.style.textDecoration === 'line-through') {
                tsInput.value = timestamp;
                textSpan.style.textDecoration = '';
            } else if (tsInput.value) {
                tsInput.value = '';
                textSpan.style.textDecoration = 'line-through';
            } else {
                tsInput.value = timestamp;
            }
            updateTimestampButtonIcon(tsButton, tsInput, textSpan);
        });
        renderedMeasures.add('M009');
      }
    }
  };

   // Wenn BFM-Maßnahmen vorhanden sind, aber kein Forensik-Wissen besteht, füge M009 hinzu.
  const hasBfmMeasuresInitially = list.some(id => id.startsWith('BFM'));
  if (hasBfmMeasuresInitially && forensicsSelect?.value === 'noforensics') {
    addM009IfNeeded();
  }

  // Fügt eine Maßnahme dynamisch zur Tabelle hinzu.
  const addMeasureDynamically = (id: string, targetTableBody: HTMLTableSectionElement, renderedMeasuresSet: Set<string>) => {
    if (!renderedMeasuresSet.has(id)) {
      const measureText = allMeasures[id];
      if (measureText) {
        const row = targetTableBody.insertRow();
        row.setAttribute('data-measure-id', id); // Wichtig für die Phasen-Balken

        // Zelle 1: Timestamp
        const cell1 = row.insertCell();
        const tsButton = document.createElement('button');
        tsButton.className = 'btn-secondary';
        tsButton.title = 'Set current time';
        tsButton.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>`;
        cell1.appendChild(tsButton);
        const tsInput = document.createElement('input');
        tsInput.type = 'text';
        tsInput.className = 'timestamp-input';
        tsInput.placeholder = 'dd.mm.yyyy hh:mm:ss';
        cell1.appendChild(tsInput);

        // Zelle 2: Maßnahme
        const cell2 = row.insertCell();
        const textSpan = document.createElement('span');
        textSpan.className = 'measure-text';
        if (id === 'BFM001') {
          textSpan.textContent = `${measureCounter}. ${measureText} (${id})`;
        } else {
          textSpan.innerHTML = `<i style="color: #6cb2eb;">${measureCounter}. ${measureText} (${id})</i>`;
        }
        measureCounter++;
        cell2.appendChild(textSpan);

        // Zelle 3: Interaktion (leer)
        row.insertCell();

        // Initialen Icon-Status setzen
        updateTimestampButtonIcon(tsButton, tsInput, textSpan);

        tsButton.addEventListener('click', () => {
            const now = new Date();
            const timestamp = `${pad(now.getDate())}.${pad(now.getMonth() + 1)}.${now.getFullYear()} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
            if (textSpan.style.textDecoration === 'line-through') {
                tsInput.value = timestamp;
                textSpan.style.textDecoration = '';
            } else if (tsInput.value) {
                tsInput.value = '';
                textSpan.style.textDecoration = 'line-through';
            } else {
                tsInput.value = timestamp;
            }
            updateTimestampButtonIcon(tsButton, tsInput, textSpan);
        });

        renderedMeasuresSet.add(id);
        return row;
      }
    }
    return null;
  };
  const answeredNoForDnsCheck = new Set<string>();
  const dnsCheckPresent = list.includes('IM011') && list.includes('IM032');
  const answeredNoForCriticalChecks = new Set<string>();

  // Prüft, ob basierend auf den Antworten des Benutzers ein False Positive vorliegt.
  const checkAndShowFalsePositive = (answeredSet: Set<string>): boolean => {
    // Definiere die relevanten Maßnahmen für diesen Check.
    const relevantMeasures = ['IM011', 'IM032', 'IM003'];
  
    // Prüfe, ob ALLE relevanten Maßnahmen überhaupt im Plan sind.
    const allRelevantMeasuresInList = relevantMeasures.every(id => list.includes(id));
  
    // Wenn nicht alle im Plan sind, kann diese spezielle FP-Bedingung nicht eintreten.
    if (!allRelevantMeasuresInList) return false;
  
    // Prüfe, ob für ALLE relevanten Maßnahmen "no" geantwortet wurde.
    const allAnsweredNo = relevantMeasures.every(id => answeredSet.has(id));
  
    if (allAnsweredNo) {
      const fpRow = targetTableBody.insertRow();
      fpRow.insertCell(); // Leere Zelle 1
      const fpCell = fpRow.insertCell(); // Zelle 2
      fpRow.insertCell(); // Leere Zelle 3
      fpCell.innerHTML = `<span class="measure-text" style="color: #c0392b;">False Positive (based on IM011, IM032 & IM003 checks)</span>`;
      return true; // Signalisiert, dass die Abarbeitung stoppen soll.
    }
    return false;
  };

 

  // Fügt kontextabhängige Meldepflichten hinzu, wenn kritische Dienste betroffen sind.
  const addCriticalityReportingMeasures = (targetTableBody: HTMLTableSectionElement, renderedMeasuresSet: Set<string>) => {
    const compliance = loadCompliance();
    if (!compliance) return;
  
    const allSelectedContexts = new Set([
      ...(compliance.regulatory ?? []),
      ...(compliance.voluntary ?? [])
    ]);

    const reportingMap: Record<string, string> = {
      'NIS-2': 'M034',
      'BSIG & German IT Security Act 2.0': 'M035',
      'BAIT / VAIT / KAIT / ZAIT': 'M051',
      'EnergieKRITIS / EnWG §11': 'M052',
      'TKG': 'M050',
      'DORA': 'M036',
      'SOC 2': 'M053',
      'ISO 27001': 'M033',
      'BSI IT-Grundschutz': 'M054',
      'C5': 'M055',
      'TISAX': 'M056'
    };
    const isoMeasuresToAdd: { id: string; text: string }[] = [];
    for (const [setting, measureId] of Object.entries(reportingMap)) {
      if (allSelectedContexts.has(setting) && !renderedMeasuresSet.has(measureId)) {
        const measureText = allMeasures[measureId];
        if (measureText) {
          isoMeasuresToAdd.push({ id: measureId, text: measureText });
        }
      }
    }
    measureCounter = renderGroupedMeasures(isoMeasuresToAdd, 'Inform the company Information Security Officer & keep informed about latest discoveries:', ISO_PREFIX, targetTableBody, renderedMeasuresSet, measureCounter);
  };

  // Fügt M046 ("Involve your IT Forensics Team") hinzu, wenn bestimmte Trigger erfüllt sind.
  const addForensicsTeamMeasureIfNeeded = (newlyAddedMeasures: string[], renderedMeasuresSet: Set<string>, targetTableBody: HTMLTableSectionElement) => {
    const forensicsLevel = getForensicsLevel();

    // M046 wird nie angezeigt, wenn keine Forensik-Anforderungen bestehen.
    if (forensicsLevel === 'noforensics') {
      return;
    }

    const isTriggeredByReporting = newlyAddedMeasures.some(code => /^M0(3[0-6]|5[0-5])$/.test(code));
    const isTriggeredByIM032 = newlyAddedMeasures.includes('IM032');

    // Wenn einer der Trigger zutrifft und M046 noch nicht gerendert wurde:
    if ((isTriggeredByReporting || isTriggeredByIM032) && !renderedMeasuresSet.has('M046')) {
      // Text dynamisch basierend auf dem Forensik-Level anpassen
      const measureText = forensicsLevel === 'profforensics'
        ? 'Involve your IT Forensics Team -> Forensic compliance requirements are high'
        : 'Involve your IT Forensics Team -> Forensic compliance requirements are moderate';

      if (measureText) {
        const row = targetTableBody.insertRow();
        row.setAttribute('data-measure-id', 'M046');

        // Zelle 1: Timestamp
        const cell1 = row.insertCell();
        const tsButton = document.createElement('button');
        tsButton.className = 'btn-secondary';
        tsButton.title = 'Set current time';
        tsButton.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>`;
        cell1.appendChild(tsButton);
        const tsInput = document.createElement('input');
        tsInput.type = 'text';
        tsInput.className = 'timestamp-input';
        tsInput.placeholder = 'dd.mm.yyyy hh:mm:ss';
        cell1.appendChild(tsInput);

        // Zelle 2: Maßnahme
        const cell2 = row.insertCell();
        const textSpan = document.createElement('span');
        textSpan.className = 'measure-text';
        textSpan.innerHTML = `<i style="color: #6cb2eb;">${measureCounter}. ${measureText} (M046)</i>`;
        measureCounter++;
        cell2.appendChild(textSpan);

        // Zelle 3: Interaktion (leer)
        row.insertCell();

        // Initial icon update
        updateTimestampButtonIcon(tsButton, tsInput, textSpan); // Initialen Icon-Status setzen

        tsButton.addEventListener('click', () => {
            const now = new Date();
            const timestamp = `${pad(now.getDate())}.${pad(now.getMonth() + 1)}.${now.getFullYear()} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
        
            if (textSpan.style.textDecoration === 'line-through') {
                tsInput.value = timestamp;
                textSpan.style.textDecoration = '';
            } else if (tsInput.value) {
                tsInput.value = '';
                textSpan.style.textDecoration = 'line-through';
            } else {
                tsInput.value = timestamp;
            }
            updateTimestampButtonIcon(tsButton, tsInput, textSpan);
        });
        renderedMeasuresSet.add('M046');
        
        // Wenn M046 hinzugefügt wird, stelle sicher, dass auch M009 hinzugefügt wird.
        addM009IfNeeded();
      }
    }
  };

  // Erstellt einen Prompt zur Abfrage der Kritikalität einer Maßnahme.
  const createCriticalityPrompt = (measureId: string, interactionCell: HTMLTableCellElement, onYes: () => void, onNo: () => void) => {
    const prompt = document.createElement('div');
    prompt.className = 'criticality-prompt';
    prompt.innerHTML = `
      <div class="form-group" style="margin-top:.75rem">
        <label style="font-weight:600;display:block;margin-bottom:.25rem">Will this significantly impair the functionality of critical services?</label>
        <div style="display:flex;gap:.5rem">
          <button type="button" class="btn">yes/not sure</button>
          <button type="button" class="btn">no</button>
        </div>
      </div>
    `;
    interactionCell.appendChild(prompt);

    const [yesBtn, noBtn] = prompt.querySelectorAll('button');

    yesBtn?.addEventListener('click', () => {
      prompt.innerHTML = 'Impairs critical services: yes/not sure';
      onYes();
    });

    noBtn?.addEventListener('click', () => {
      prompt.innerHTML = 'Impairs critical services: no';
      onNo();
    });
  };

  // Fügt eine initiale Dokumentationsmaßnahme (M031 oder M032) hinzu, wenn Compliance-Anforderungen ausgewählt sind.
  const compliance = loadCompliance();
  const allSelectedContexts = [
    ...(compliance?.regulatory ?? []),
    ...(compliance?.voluntary ?? [])
  ];

  if (allSelectedContexts.length > 0) {
    let measureIdToAdd: string | null = null;

    if (allSelectedContexts.length === 1 && allSelectedContexts[0] === 'TKG') { // Nur TKG ausgewählt
      measureIdToAdd = 'M032';
    } else {
      measureIdToAdd = 'M031';
    }

    if (measureIdToAdd && !renderedMeasures.has(measureIdToAdd)) {
      const measureText = allMeasures[measureIdToAdd];
      const row = targetTableBody.insertRow(0); // An oberster Stelle einfügen
      row.setAttribute('data-measure-id', measureIdToAdd);
      renderedMeasures.add(measureIdToAdd);

      const cell1 = row.insertCell(); // Timestamp
      const cell2 = row.insertCell(); // Maßnahme
      row.insertCell(); // Leere Interaktionszelle

      const textSpan = document.createElement('span');
      textSpan.className = 'measure-text';
      textSpan.innerHTML = `<i style="color: #6cb2eb;">0. ${measureText} (${measureIdToAdd})</i>`;
      cell2.appendChild(textSpan);

      // Timestamp-Button hinzufügen und Logik binden
      const { tsButton, tsInput } = addTimestampControls(cell1, textSpan);
      updateTimestampButtonIcon(tsButton, tsInput, textSpan);
    }
  }

  // Startet die iterative Abarbeitung und das Rendern der Maßnahmenliste.
  const continueFrom = (startIdx: number) => {
    for (let i = startIdx; i < list.length; i++) {
      const id = list[i];

      // KORREKTUR: Logik, um M016 zu überspringen, wenn IM014 mit "no" beantwortet wurde.
      if (id === 'M016' && suspiciousNoAnswers.has('IM014')) {
        continue;
      }

      // KORREKTUR: Wenn IM022 und IM033 mit "no" beantwortet wurden, überspringe M037
      if (id === 'M037' && suspiciousNoAnswers.has('IM022') && suspiciousNoAnswers.has('IM033')) {
        continue;
      }

      if (id === 'M046') {
        const forensicsLevel = getForensicsLevel();
        if (forensicsLevel === 'noforensics') {
          continue; // Überspringe das Rendern von M046
        }
        addMeasureToListIfNeeded('M009', i);
      }

      // NEU: Wenn IM033 mit "no" beantwortet wurde, überspringe IM034, IM013, IM036
      if (suspiciousNoAnswers.has('IM033')) {
        const measuresToSkip = ['IM034', 'IM013', 'IM036'];
        if (measuresToSkip.includes(id)) {
          continue;
        }
      }

      // NEU: Logik, um M025 zu überspringen, wenn IM036 mit "no" beantwortet wurde.
      if (id === 'M025' && suspiciousNoAnswers.has('IM036')) {
        continue; // Überspringe das Rendern von M025
      }

      // KORREKTUR: Logik, um M039 zu überspringen, wenn IM014 mit "no" beantwortet wurde.
      if (suspiciousNoAnswers.has('IM022')) {
        const measuresToRemove = ['M026', 'M027', 'M028', 'M003', 'M018'];
        if (measuresToRemove.includes(id)) {
          continue;
        }
      }


      // KORREKTUR: Logik, um M039 zu überspringen, wenn IM014 mit "no" beantwortet wurde.
      if (id === 'M039') {
        // Wenn IM014 mit "no" beantwortet wurde, wird M039 nicht mehr angezeigt.
        if (suspiciousNoAnswers.has('IM014')) {
          continue; // Überspringe das Rendern von M039
        }
      }

      // Logik für "not sure": Füge BFM001 vor den Recovery-Maßnahmen hinzu.
      const shouldAddBfm001 = notSureWasSelected && ['M048', 'M043', 'M005'].includes(id);
      if (shouldAddBfm001 && !bfm001Added) {
        addMeasureDynamically('BFM001', targetTableBody, renderedMeasures);
        bfm001Added = true;
        redrawBars();
      }

      // KORREKTUR: Die Variable `li` muss NACH der Prüfung von `txt` deklariert werden.
      const txt = allMeasures[id];
      if (!txt) continue;
      if (renderedMeasures.has(id)) continue; // Überspringe bereits gerenderte Maßnahmen (wie M031/M032)
      const row = targetTableBody.insertRow();
      renderedMeasures.add(id); // Füge die aktuelle Maßnahme dem Set hinzu
      row.setAttribute('data-measure-id', id);

      // --- Zelle 1: Timestamp ---
      const cell1 = row.insertCell();
      cell1.style.width = '185px';
      const tsButton = document.createElement('button');
      tsButton.className = 'btn-secondary';
      tsButton.title = 'Set current time';
      tsButton.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>`;
      cell1.appendChild(tsButton);

      const tsInput = document.createElement('input');
      tsInput.type = 'text';
      tsInput.className = 'timestamp-input';
      tsInput.placeholder = 'dd.mm.yyyy hh:mm:ss';
      cell1.appendChild(tsInput);

      // --- Zelle 2: Maßnahmentext ---
      const cell2 = row.insertCell();
      const textSpan = document.createElement('span');
      textSpan.className = 'measure-text';

      // --- Zelle 3: Interaktion / Ergebnis ---
      const cell3 = row.insertCell();

      tsButton.addEventListener('click', () => {
          const now = new Date();
          const timestamp = `${pad(now.getDate())}.${pad(now.getMonth() + 1)}.${now.getFullYear()} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;

          if (textSpan.style.textDecoration === 'line-through') {
              tsInput.value = timestamp;
              textSpan.style.textDecoration = '';
          } else if (tsInput.value) {
              tsInput.value = '';
              textSpan.style.textDecoration = 'line-through';
          } else {
              tsInput.value = timestamp;
          }
          updateTimestampButtonIcon(tsButton, tsInput, textSpan);
      });

      redrawBars(); // KORREKTUR: Balken nach dem Hinzufügen jedes Elements neu zeichnen.

      const highlightIds = new Set([
        'M009', 'M030', 'M032', 'M033', 'M034', 'M035', 'M036', 'M046',
        'M050', 'M051', 'M052', 'M053', 'M054', 'M055'
      ]);

      if (highlightIds.has(id)) {
        if (id === 'M046') {
          const forensicsLevel = getForensicsLevel();
          const dynamicText = forensicsLevel === 'profforensics'
            ? 'Involve your IT Forensics Team -> Forensic compliance requirements are high'
            : 'Involve your IT Forensics Team -> Forensic compliance requirements are moderate';
          textSpan.innerHTML = `<i style="color: #6cb2eb;">${measureCounter}. ${dynamicText} (M046)</i>`;
        } else {
          textSpan.innerHTML = `<i style="color: #6cb2eb;">${measureCounter}. ${txt} (${id})</i>`;
        }
      } else {
        textSpan.textContent = `${measureCounter}. ${txt} (${id})`;
      }
      measureCounter++;
      cell2.appendChild(textSpan);

      // Initial icon update
      updateTimestampButtonIcon(tsButton, tsInput, textSpan);

      const isCriticalAction = id === 'M001' || id === 'M002' || id === 'M003';
      if (isCriticalAction) {
        createCriticalityPrompt(id, cell3,
          () => { // onYes
            if (id === 'M001' || id === 'M002' || id === 'M003') {
              // Füge eine Notfallmaßnahme hinzu
              const emergencyRow = targetTableBody.insertRow();

              // Zelle 1: Timestamp
              const emergencyCell1 = emergencyRow.insertCell();
              const emergencyTsButton = document.createElement('button');
              emergencyTsButton.className = 'btn-secondary';
              emergencyTsButton.title = 'Set current time';
              emergencyTsButton.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>`;
              emergencyCell1.appendChild(emergencyTsButton);
              const emergencyTsInput = document.createElement('input');
              emergencyTsInput.type = 'text';
              emergencyTsInput.className = 'timestamp-input';
              emergencyTsInput.placeholder = 'dd.mm.yyyy hh:mm:ss';
              emergencyCell1.appendChild(emergencyTsInput);

              // Zelle 2: Maßnahme
              const emergencyCell2 = emergencyRow.insertCell();
              const emergencyTextSpan = document.createElement('span');
              emergencyTextSpan.className = 'measure-text';
              emergencyTextSpan.innerHTML = `<i class="measure-pink" style="color: #e53e3e;">${measureCounter}. Initiate internal emergency procedures for the services affected by this measure</i>`;
              measureCounter++;
              emergencyCell2.appendChild(emergencyTextSpan);

              // Zelle 3: Interaktion (leer)
              emergencyRow.insertCell();

              emergencyTsButton.addEventListener('click', () => {
                  const now = new Date();
                  const timestamp = `${pad(now.getDate())}.${pad(now.getMonth() + 1)}.${now.getFullYear()} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;

                  if (emergencyTextSpan.style.textDecoration === 'line-through') {
                      emergencyTsInput.value = timestamp;
                      emergencyTextSpan.style.textDecoration = '';
                  } else if (emergencyTsInput.value) {
                      emergencyTsInput.value = '';
                      emergencyTextSpan.style.textDecoration = 'line-through';
                  } else {
                      emergencyTsInput.value = timestamp;
                  }
                  updateTimestampButtonIcon(emergencyTsButton, emergencyTsInput, emergencyTextSpan);
              });
              // Wenn kritische Dienste betroffen sind, füge M009 hinzu.
              addM009IfNeeded();

              const measuresBefore = new Set(renderedMeasures);
              addCriticalityReportingMeasures(targetTableBody, renderedMeasures); // Neue Meldepflichten hinzufügen
              const measuresAfter = new Set(renderedMeasures);
              const newlyAdded = [...measuresAfter].filter(m => !measuresBefore.has(m));
              
              // Prüfe, ob M046 hinzugefügt werden muss
              addForensicsTeamMeasureIfNeeded(newlyAdded, renderedMeasures, targetTableBody);
              redrawBars(); // KORREKTUR: Balken nach dynamischem Hinzufügen neu zeichnen.
            }
            continueFrom(i + 1);
          },
          () => { // onNo
            redrawBars();
            continueFrom(i + 1);
          });
        return; // Warten auf Benutzerantwort
      }

      if (id === 'M024') {
      }

      if (id === 'M017') {
        const prompt = document.createElement('div');
        prompt.className = 'criticality-prompt';
        prompt.innerHTML = `
          <div class="form-group" style="margin-top:.75rem">
            <label style="font-weight:600;display:block;margin-bottom:.25rem">Criticality of Data</label>
            <select id="criticality-select">
              <option value="low">Low (unusable)</option>
              <option value="medium">Medium (no personal data, no company secrets)</option>
              <option value="high_personal">High (personal data)</option>
              <option value="high_secrets">High (company secrets)</option>
              <option value="high_both">High (personal data & company secrets)</option>
            </select>
            <div style="margin-top:.5rem">
              <button type="button" id="crit-continue" class="btn">Continue</button>
            </div>
          </div>
        `;
        cell3.appendChild(prompt);

        const contBtn = prompt.querySelector('#crit-continue') as HTMLButtonElement | null;
        const select  = prompt.querySelector('#criticality-select') as HTMLSelectElement | null;
        contBtn?.addEventListener('click', () => {
            // Auswahltext für die Anzeige holen
            const selectedOption = select?.options[select.selectedIndex];
            const selectedText = selectedOption ? selectedOption.text : 'unknown';

            const val   = select?.value || '';
            const compliance  = (typeof loadCompliance === 'function') ? loadCompliance() : {};
            const regs = [
              ...((compliance?.regulatory) ?? []),
              ...((compliance?.voluntary)  ?? []),
            ];

            const isGDPR = regs.includes('EU-GDPR & BDSG') || (typeof isGdprSelected === 'function' && isGdprSelected());

            const selectedPersonal = val === 'high_personal' || val === 'high_both';
            const selectedSecrets  = val === 'high_secrets'  || val === 'high_both';

            cell3.innerHTML = `Criticality: ${selectedText}`;

            // Maßnahmen gemäß deiner Regeln sammeln
            const dpoMeasures: { id: string; text: string }[] = [];
            const isoMeasures: { id: string; text: string }[] = [];

            // --- PERSONENBEZOGENE DATEN ---
            if (selectedPersonal && isGDPR) {
                const measureId = 'M030';
                if (!renderedMeasures.has(measureId)) {
                    dpoMeasures.push({ id: measureId, text: allMeasures[measureId] });
                }
            }

            // --- COMPANY SECRETS ---
            if (selectedSecrets && regs.includes('ISO 27001')) {
                const measureId = 'M033';
                if (!renderedMeasures.has(measureId)) {
                    isoMeasures.push({ id: measureId, text: allMeasures[measureId] });
                }
            }

             if (selectedSecrets && regs.includes('C2')) {
                const measureId = 'M055';
                if (!renderedMeasures.has(measureId)) {
                    isoMeasures.push({ id: measureId, text: allMeasures[measureId] });
                }
            }

            if (selectedSecrets && regs.includes('NIS-2')) {
                const measureId = 'M034';
                if (!renderedMeasures.has(measureId)) {
                    isoMeasures.push({ id: measureId, text: allMeasures[measureId] });
                }
            }
            if (selectedSecrets && regs.includes('BSIG & German IT Security Act 2.0')) {
                const measureId = 'M035';
                if (!renderedMeasures.has(measureId)) {
                    isoMeasures.push({ id: measureId, text: allMeasures[measureId] });
                }
            }
            if (selectedSecrets && regs.includes('DORA')) {
                const measureId = 'M036';
                if (!renderedMeasures.has(measureId)) {
                    isoMeasures.push({ id: measureId, text: allMeasures[measureId] });
                }
            }

            // KORREKTUR: TISAX (M056) muss ebenfalls zur isoMeasures-Liste hinzugefügt werden.
            if (selectedSecrets && regs.includes('TISAX')) {
                const measureId = 'M056';
                if (!renderedMeasures.has(measureId)) {
                    isoMeasures.push({ id: measureId, text: allMeasures[measureId] });
                }
            }
                        
            if (selectedSecrets && regs.includes('BAIT')) {
                const measureId = 'M051';
                if (!renderedMeasures.has(measureId)) {
                    isoMeasures.push({ id: measureId, text: allMeasures[measureId] });
                }
            }

                        
            if (selectedSecrets && regs.includes('KRITIS')) {
                const measureId = 'M052';
                if (!renderedMeasures.has(measureId)) {
                    isoMeasures.push({ id: measureId, text: allMeasures[measureId] });
                }
            }

                        
            if (selectedSecrets && regs.includes('TKG')) {
                const measureId = 'M050';
                if (!renderedMeasures.has(measureId)) {
                    isoMeasures.push({ id: measureId, text: allMeasures[measureId] });
                }
            }

            measureCounter = renderGroupedMeasures(dpoMeasures, 'Inform the company Data Protection Officer & keep informed about latest discoveries:', DPO_PREFIX, targetTableBody, renderedMeasures, measureCounter);
            measureCounter = renderGroupedMeasures(isoMeasures, 'Inform the company Information Security Officer & keep informed about latest discoveries:', ISO_PREFIX, targetTableBody, renderedMeasures, measureCounter);

            const newlyAddedCodes = [...dpoMeasures, ...isoMeasures].map(m => m.id);
            addForensicsTeamMeasureIfNeeded(newlyAddedCodes, renderedMeasures, targetTableBody);
            redrawBars(); // KORREKTUR: Balken nach dynamischem Hinzufügen neu zeichnen.

            continueFrom(i + 1);
          });


        return; // Warten auf Auswahl
      }

      if (id === 'IM012') {
        const prompt = document.createElement('div');
        prompt.className = 'fp-prompt'; // Re-use existing style
        prompt.innerHTML = `
          <div class="form-group" style="margin-top:.75rem">
            <label style="font-weight:600;display:block;margin-bottom:.25rem">Malicious artifact(s) executed?</label>
            <div style="display:flex;gap:.5rem">
              <button type="button" class="btn">yes/not sure</button>
              <button type="button" class="btn">no</button>
            </div>
          </div>
        `;
        cell3.appendChild(prompt);

        const [yesBtn, noBtn] = prompt.querySelectorAll('button');

        yesBtn?.addEventListener('click', () => {
          prompt.innerHTML = 'Executed: yes/not sure';
          continueFrom(i + 1);
        });

        noBtn?.addEventListener('click', () => {
          prompt.innerHTML = 'Executed: no';
          continueFrom(i + 1);
          redrawBars();
        });
        return; // Warten auf Benutzerantwort
      }

      // Interaktive Abfrage für investigative Maßnahmen
      const measuresWithSuspiciousPrompt = new Set([
        'IM003', 'IM004', 'IM005', 'IM007', 'IM011', 'IM022', 'IM032', 'IM033', 'IM014', 'IM041', 'IM034', 'IM036'
      ]);
      if (measuresWithSuspiciousPrompt.has(id)) {
        const prompt = document.createElement('div');
        prompt.className = 'fp-prompt';
        prompt.innerHTML = `
          <div class="form-group" style="margin-top:.75rem">
            <label style="font-weight:600;display:block;margin-bottom:.25rem">Anything suspicious?</label>
            <div style="display:flex;gap:.5rem">
              <button type="button" class="btn">yes</button>
              <button type="button" class="btn">not sure</button>
              <button type="button" class="btn">no</button>
            </div>
          </div>
        `;
        cell3.appendChild(prompt);

        const [yesBtn, notSureBtn, noBtn] = prompt.querySelectorAll('button');

        noBtn?.addEventListener('click', () => {
          prompt.innerHTML = 'Suspicious: no';

          if (id === 'IM014' || id === 'IM032' || id === 'IM022' || id === 'IM036' || id === 'IM033') {
            suspiciousNoAnswers.add(id);
          }

          // Sonderregel: Bei bestimmten IMs wird bei "no" von einem False Positive ausgegangen.
          const falsePositiveOnNo = ['IM003', 'IM005'];
          if (falsePositiveOnNo.includes(id)) {
            const fpRow = targetTableBody.insertRow();
            fpRow.insertCell(); // Leere Zelle 1
            const fpCell = fpRow.insertCell(); // Zelle 2 für die Nachricht
            fpRow.insertCell(); // Leere Zelle 3

            if (id === 'IM003') {
              fpCell.innerHTML = `<span class="measure-text" style="color: #c0392b;">Either you have the wrong file or it is a false positive.</span>`;
            } else {
              fpCell.innerHTML = `<span class="measure-text" style="color: #c0392b;">False Positive</span>`;
            }
            redrawBars(); // KORREKTUR: Balken aktualisieren.
            // Keine weiteren Schritte ausführen, da der Fall als erledigt gilt.
            return;
          }

          if (dnsCheckPresent && (id === 'IM011' || id === 'IM032')) {
            answeredNoForCriticalChecks.add(id);
          }
          if (id === 'IM003') {
            answeredNoForCriticalChecks.add(id);
          }

          if (checkAndShowFalsePositive(answeredNoForCriticalChecks)) {
            redrawBars();
            return; // Abarbeitung stoppen
          }
          if (id === 'IM041') {
            // KORREKTUR: Füge M043 nur hinzu, wenn es nicht bereits in der ursprünglichen Liste war, um Duplikate zu vermeiden.
            const originalListContainsM043 = tacticToActionMap[tacticInput?.value.trim().split(' ')[0] ?? '']?.includes('M043');
            if (!originalListContainsM043) {
              addMeasureDynamically('M043', targetTableBody, renderedMeasures); // Bei "no" (Backup OK) -> von sauberem Backup wiederherstellen
              redrawBars(); // Balken nach dynamischem Hinzufügen neu zeichnen.
            }
          }
          continueFrom(i + 1);
        });

        yesBtn?.addEventListener('click', () => {
          prompt.remove(); // Prompt entfernen
          cell3.innerHTML = 'Suspicious: yes'; // Angepassten Text anhängen

          // Antwort im Zustand speichern
          suspiciousAnswers.add(id);
          addM020IfNeeded(); // Prüfen, ob M020 jetzt hinzugefügt werden muss

          if (id === 'IM022') {
            addMeasureToListIfNeeded('M003', i);
          }

          if (id === 'IM032') {
            addMeasureToListIfNeeded('M039', i);
            addForensicsTeamMeasureIfNeeded([id], renderedMeasures, targetTableBody);
          }

          if (id === 'IM041') {
            // Ersetze M043 (Restore) durch M048 (Reimage) in der verbleibenden Liste.
            const m043Index = list.indexOf('M043');
            if (m043Index > -1) {
              list[m043Index] = 'M048';
            }
          }

          continueFrom(i + 1);
        });

        notSureBtn?.addEventListener('click', () => {
          prompt.remove();
          cell3.innerHTML = 'Suspicious: not sure'; // Angepassten Text anhängen
          notSureWasSelected = true; // NEU: Flag setzen

          // "not sure" wird wie "yes" behandelt
          suspiciousAnswers.add(id);
          addM020IfNeeded(); // Prüfen, ob M020 jetzt hinzugefügt werden muss

          if (id === 'IM032') {
            addMeasureToListIfNeeded('M039', i);
            addForensicsTeamMeasureIfNeeded([id], renderedMeasures, targetTableBody);
          }

          if (id === 'IM041') {
            // Ersetze M043 (Restore) durch M048 (Reimage) in der verbleibenden Liste.
            const m043Index = list.indexOf('M043');
            if (m043Index > -1) {
              list[m043Index] = 'M048';
            }
          }

          continueFrom(i + 1);
        });

        return; // Warten auf Antwort
      }
    }
  };
  function drawPhaseBars(renderedTableBody: HTMLTableSectionElement, phasesContainer: HTMLDivElement) {
    // KORREKTUR: Die gesamte Logik wurde überarbeitet, um die Positionierung mit getBoundingClientRect zu reparieren.
    if (!phasesContainer || !renderedTableBody || !renderedTableBody.parentElement) return;
  
      phasesContainer.innerHTML = ''; // Container leeren
      const renderedItems = Array.from(renderedTableBody.children) as HTMLTableRowElement[];
      if (renderedItems.length === 0) return;

      const phasePositions: Record<string, { top: number, bottom: number }> = {};

      // Finde die Start- und Endposition für jede Phase
      renderedItems.forEach(row => {
          const measureId = row.getAttribute('data-measure-id');
          if (!measureId) return;

          const phase = measureToPhaseMap[measureId];
          if (phase) {
              const top = row.offsetTop;
              const bottom = top + row.offsetHeight;

              if (!phasePositions[phase]) {
                  phasePositions[phase] = { top, bottom };
              } else {
                  phasePositions[phase].bottom = bottom; // Immer die unterste Position aktualisieren
              }
          }
      });

      // Erstelle und positioniere die Balken
      phaseOrder.forEach((phase, index) => {
          const positions = phasePositions[phase];
          if (!positions) return;

          const bar = document.createElement('div');
          bar.className = 'phase-bar';
          bar.style.backgroundColor = phaseColors[phase] || '#ccc';
          bar.style.left = `${index * 25}px`;
          bar.innerHTML = `<span class="phase-label" style="font-family: Helvetica, sans-serif; letter-spacing: 0.5px; font-size: larger; font-weight: normal;">${phase}</span>`;
          bar.style.top = `${positions.top}px`;
          bar.style.height = `${positions.bottom - positions.top}px`;

          phasesContainer.appendChild(bar);
      });
  }

  const redrawBars = () => setTimeout(() => drawPhaseBars(targetTableBody, phasesContainer), 10);

  continueFrom(0);
}

/**
 * Erstellt und bindet Timestamp-Steuerelemente für eine Tabellenzelle.
 * @param cell Die Zelle, in der die Steuerelemente platziert werden.
 * @param textSpan Das Span-Element, dessen Textdekoration gesteuert wird.
 * @returns Die erstellten Button- und Input-Elemente.
 */
function addTimestampControls(cell: HTMLTableCellElement, textSpan: HTMLSpanElement) {
  const pad = (n: number) => String(n).padStart(2, '0');
  const tsButton = document.createElement('button');
  tsButton.className = 'btn-secondary';
  tsButton.title = 'Set current time';
  cell.appendChild(tsButton);

  const tsInput = document.createElement('input');
  tsInput.type = 'text';
  tsInput.className = 'timestamp-input';
  tsInput.placeholder = 'dd.mm.yyyy hh:mm:ss';
  cell.appendChild(tsInput);

  tsButton.addEventListener('click', () => {
    const now = new Date();
    const timestamp = `${pad(now.getDate())}.${pad(now.getMonth() + 1)}.${now.getFullYear()} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
    tsInput.value = tsInput.value && textSpan.style.textDecoration !== 'line-through' ? '' : timestamp;
    textSpan.style.textDecoration = tsInput.value ? (textSpan.style.textDecoration === 'line-through' ? '' : (tsInput.value ? '' : 'line-through')) : 'line-through';
    updateTimestampButtonIcon(tsButton, tsInput, textSpan);
  });

  return { tsButton, tsInput };
}
// ---------- 8) Phasen-Konfiguration für Visualisierung ----------
const measureToPhaseMap: Record<string, string> = {
  // Detect
  ...Object.keys(investigativeMeasures).reduce((acc, key) => ({ ...acc, [key]: 'Detect' }), {}),
  ...Object.keys(basicForensicMeasures).reduce((acc, key) => ({ ...acc, [key]: 'Detect' }), {}),
  ...Object.keys(professionalForensicMeasures).reduce((acc, key) => ({ ...acc, [key]: 'Detect' }), {}),
  'M014': 'Detect', 'M029': 'Detect', 'M017': 'Detect',

  // Respond
  'M001': 'Respond', 'M002': 'Respond', 'M003': 'Respond', 'M004': 'Respond',
  'M006': 'Respond', 'M007': 'Respond', 'M008': 'Respond', 'M009': 'Respond',
  'M010': 'Respond', 'M011': 'Respond', 'M012': 'Respond', 'M013': 'Respond',
  'M015': 'Respond', 'M016': 'Respond', 'M018': 'Respond', 'M019': 'Respond',
  'M023': 'Respond', 'M024': 'Respond', 'M025': 'Respond', 'M026': 'Respond',
  'M027': 'Respond', 'M028': 'Respond', 'M037': 'Respond', 'M039': 'Respond',
  'M041': 'Respond', 'M042': 'Respond', 'M046': 'Respond',

  // Recover
  'M005': 'Recover', 'M022': 'Recover', 'M040': 'Recover', 'M043': 'Recover',
  'M044': 'Recover', 'M045': 'Recover', 'M047': 'Recover', 'M048': 'Recover',
  'M020': 'Recover',

  // Govern
  'M030': 'Govern', 'M031': 'Govern', 'M032': 'Govern', 'M033': 'Govern', 'M034': 'Govern', 'M035': 'Govern',
  'M036': 'Govern', 'M050': 'Govern', 'M051': 'Govern', 'M052': 'Govern',
  'M053': 'Govern', 'M054': 'Govern', 'M055': 'Govern', 'M056': 'Govern',
};

const phaseOrder = ['Govern', 'Detect', 'Respond', 'Recover'];
const phaseColors: Record<string, string> = {
  'Detect': '#7d0086ff',    // Dunkleres Blau
  'Respond': '#e036c4ff',   // Dunkleres Gelb/Orange
  'Recover': '#959296ff',   // Dunkleres Grün
  'Govern': '#442cadff',    // Lila
};

/**
 * Wandelt eine RGB-Farbzeichenfolge in einen Hex-Code um.
 * @param rgb Die RGB-Zeichenfolge (z. B. "rgb(255, 0, 0)").
 * @returns Der Hex-Code (z. B. "#ff0000").
 */
function rgbToHex(rgb: string): string {
    const result = /rgb\((\d+),\s*(\d+),\s*(\d+)\)/.exec(rgb);
    if (!result) return rgb;
    return "#" + [1, 2, 3].map(i => parseInt(result[i]).toString(16).padStart(2, '0')).join('');
}

/**
 * Erstellt eine saubere HTML-Repräsentation einer Tabelle mit Inline-Stilen
 * und kopiert diese in die Zwischenablage, optimiert für das Einfügen in Word/Outlook.
 * @param tableElement Die zu kopierende HTML-Tabelle.
 * @param feedbackElementId Die ID des Elements, das Feedback anzeigt.
 */
function copyTableWithStyles(tableElement: HTMLTableElement | null, feedbackElementId: string) {
  if (!tableElement) return;

  // 1. Erstelle eine saubere Kopie der Tabelle im Speicher
  const cleanTable = document.createElement('table');
  cleanTable.setAttribute('style', 'border-collapse: collapse; width: 100%; font-family: sans-serif; font-size: 14px;');

  // Kopfzeile kopieren
  const thead = tableElement.querySelector('thead')?.cloneNode(true) as HTMLTableSectionElement;
  thead.querySelectorAll('th').forEach(th => {
    th.setAttribute('style', 'border: 1px solid #cccccc; text-align: left; padding: 8px; background-color: #f2f2f2; color: #333333; font-weight: bold;');
  });
  cleanTable.appendChild(thead);

  // Körper kopieren und Stile anwenden
  const tbody = document.createElement('tbody');
  tableElement.querySelectorAll('tbody tr').forEach(row => {
    const newRow = tbody.insertRow();
    row.querySelectorAll('td').forEach((cell, cellIndex) => {
      const newCell = newRow.insertCell();
      let cellStyle = 'border: 1px solid #dddddd; padding: 8px; vertical-align: top;';

      if (cellIndex === 0) { // Timestamp-Zelle
        const input = cell.querySelector('input.timestamp-input') as HTMLInputElement | null;
        newCell.textContent = input?.value || '';
        cellStyle += ' white-space: nowrap;';
      } else if (cellIndex === 1) { // Recommended Action Zelle
        const textSpan = cell.querySelector('.measure-text');
        if (textSpan) {
          let textColor = '';
          let textDecoration = '';

          const innerI = textSpan.querySelector('i');

          // Farbe aus dem inneren <i>-Tag (für Hervorhebungen) priorisieren
          if (innerI) {
            const inlineColor = innerI.style.color;
            if (inlineColor) textColor = rgbToHex(inlineColor);
          }

          // Fallback auf die Farbe des textSpan selbst
          if (!textColor) {
            const spanColor = textSpan.style.color;
            if (spanColor) textColor = rgbToHex(spanColor);
          }

          if (textSpan.style.textDecorationLine === 'line-through' || window.getComputedStyle(textSpan).textDecorationLine === 'line-through') {
            textDecoration = 'text-decoration: line-through;';
          }

          let pStyle = 'margin:0; padding:0;';
          if (textColor) {
            pStyle += ` color: ${textColor};`;
            cellStyle += ` color: ${textColor};`;
          }
          if (textDecoration) {
            pStyle += ` ${textDecoration}`;
            cellStyle += ` ${textDecoration}`;
          }

          newCell.innerHTML = `<p style="${pStyle}">${textSpan.innerHTML}</p>`;
        } else {
          // Fallback für Zellen ohne .measure-text
          newCell.innerHTML = `<p style="margin:0; padding:0;">${cell.innerHTML}</p>`;
        }
      } else { // Andere Zellen
        newCell.innerHTML = `<p style="margin:0; padding:0;">${cell.innerHTML}</p>`;
      }
      newCell.setAttribute('style', cellStyle);
    });
  });
  cleanTable.appendChild(tbody);

  const htmlString = cleanTable.outerHTML;

  // Ansatz mit execCommand für maximale Kompatibilität mit Word/Outlook
  const tempDiv = document.createElement('div');
  tempDiv.style.position = 'absolute'; // Aus dem sichtbaren Bereich verschieben
  tempDiv.style.left = '-9999px';
  tempDiv.innerHTML = htmlString;
  document.body.appendChild(tempDiv);

  const selection = window.getSelection();
  const range = document.createRange();
  range.selectNodeContents(tempDiv);
  selection?.removeAllRanges();
  selection?.addRange(range);

  try {
    document.execCommand('copy');
    showCopyFeedback(feedbackElementId, 'Copied!', true);
  } catch (err) {
    console.error('Failed to copy: ', err);
    showCopyFeedback(feedbackElementId, 'Failed to copy!', false);
  } finally {
    // Bereinigen
    selection?.removeAllRanges();
    document.body.removeChild(tempDiv);
  }
}

// ---------- 9) Anzeige der Meldefristen ----------
function ensureDeadlineContainer(): HTMLDivElement | null {
  let container = document.getElementById('reporting-deadlines-container');
  if (container) {
    return container.querySelector('#reporting-deadlines');
  }

  const timerCard = document.querySelector('.timer-card');
  if (!timerCard) return null;

  container = document.createElement('div');
  container.id = 'reporting-deadlines-container';
  container.className = 'card-section';
  container.innerHTML = `
    <div class="actions-header">
        <h4>Legal Deadlines for Reporting Obligations</h4>
        <div class="copy-controls">
            <button id="copy-deadlines-btn" class="copy-btn" title="Copy deadlines to clipboard">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-copy"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2v2"/></svg>
            </button>
            <span id="deadlines-copy-feedback" class="copy-feedback"></span>
        </div>
    </div>
    <div id="reporting-deadlines"></div>
  `;
  timerCard.insertAdjacentElement('afterend', container);

  // Add event listener for the copy button
  const copyBtn = container.querySelector('#copy-deadlines-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const contentDiv = container?.querySelector('#reporting-deadlines') as HTMLDivElement | null;
      if (contentDiv) copyTableWithStyles(contentDiv, 'deadlines-copy-feedback'); // Annahme: contentDiv ist eine Tabelle oder soll so behandelt werden
    });
  }
  return container.querySelector('#reporting-deadlines');
}

function updateReportingDeadlines() {
  const deadlinesContainer = ensureDeadlineContainer();
  const alertStartInput = document.getElementById('alert-start') as HTMLInputElement | null;

  const startTime = new Date(alertStartInput.value.replace(' ', 'T'));
  if (!alertStartInput || !alertStartInput.value || isNaN(startTime.getTime())) {
    deadlinesContainer.innerHTML = '';
    return;
  }

  const compliance = loadCompliance();
  const regulatory = compliance?.regulatory ?? [];
  let content = '';

  const formatDeadline = (date: Date): string => {
    const pad = (n: number) => String(n).padStart(2, '0');
    const day = pad(date.getDate());
    const month = pad(date.getMonth() + 1);
    const year = date.getFullYear();
    const hours = pad(date.getHours());
    const minutes = pad(date.getMinutes());
    const seconds = pad(date.getSeconds());
    return `${day}.${month}.${year} ${hours}:${minutes}:${seconds}`;
  };

  if (regulatory.includes('EU-GDPR & BDSG')) {
    const deadline = new Date(startTime.getTime() + 72 * 60 * 60 * 1000);
    content += `<p><strong>EU-GDPR:</strong></p>
                <ul style="margin-top: -10px; margin-bottom: 10px; padding-left: 20px;">
                  <li>${formatDeadline(deadline)}</li>
                </ul>`;
  }

  if (regulatory.includes('NIS-2')) {
    const earlyWarning = new Date(startTime.getTime() + 24 * 60 * 60 * 1000);
    const incidentNotification = new Date(startTime.getTime() + 72 * 60 * 60 * 1000);
    const finalReport = new Date(startTime);
    finalReport.setDate(finalReport.getDate() + 30);

    content += `<p><strong>NIS-2:</strong></p>
                <ul style="margin-top: -10px; margin-bottom: 10px; padding-left: 20px;">
                  <li>1. Early Warning: ${formatDeadline(earlyWarning)}</li>
                  <li>2. Incident Notification: ${formatDeadline(incidentNotification)}</li>
                  <li>3. Final Report: ${formatDeadline(finalReport)}</li>
                </ul>`;
  }

  if (regulatory.includes('DORA')) {
    content += `<p><strong>DORA:</strong></p>
                <ul style="margin-top: -10px; margin-bottom: 10px; padding-left: 20px;">
                  <li>ASAP</li>
                </ul>`;
  }

  if (regulatory.includes('BSIG & German IT Security Act 2.0')) {
    content += `<p><strong>BSIG & German IT Security Act 2.0:</strong></p>
                <ul style="margin-top: -10px; margin-bottom: 10px; padding-left: 20px;">
                  <li>ASAP</li>
                </ul>`;
  }

  if (regulatory.includes('BAIT / VAIT / KAIT / ZAIT')) {
    const deadline = new Date(startTime.getTime() + 28 * 60 * 60 * 1000);
    content += `<p><strong>BAIT / VAIT / KAIT / ZAIT:</strong></p>
                <ul style="margin-top: -10px; margin-bottom: 10px; padding-left: 20px;">
                  <li>${formatDeadline(deadline)} (but 4h after classification of citicality)</li>
                </ul>`;
  }

  if (regulatory.includes('EnergieKRITIS / EnWG §11')) {
    content += `<p><strong>EnergieKRITIS / EnWG §11:</strong></p>
                <ul style="margin-top: -10px; margin-bottom: 10px; padding-left: 20px;">
                  <li>ASAP</li>
                </ul>`;
  }

  if (regulatory.includes('TKG')) {
    const deadline = new Date(startTime.getTime() + 24 * 60 * 60 * 1000);
    content += `<p><strong>TKG:</strong></p>
                <ul style="margin-top: -10px; margin-bottom: 10px; padding-left: 20px;">
                  <li>${formatDeadline(deadline)}</li>
                </ul>`;
  }

  deadlinesContainer.innerHTML = content;
}

/**
 * Initialisiert die "Alert Start Time"-Funktionalität.
 * - Setzt die aktuelle Zeit als Standard.
 * - Ermöglicht dem Benutzer, die Startzeit zu ändern.
 * - Synchronisiert die Anzeige und die abhängigen Berechnungen.
 */
function initAlertTimer() {
  const functionalInput = document.getElementById('alert-start') as HTMLInputElement | null;
  const displayInput = document.getElementById('alert-start-display') as HTMLInputElement | null;
  const elapsedTimeElement = document.getElementById('elapsed-time') as HTMLElement | null;

  if (!functionalInput || !displayInput || !elapsedTimeElement) {
    console.error('Timer-Elemente nicht gefunden. Initialisierung abgebrochen.');
    return;
  }

  let stopwatchInterval: number;

  const pad = (n: number) => String(n).padStart(2, '0');

  function toLocalISOString(d: Date): string {
    const y = d.getFullYear();
    const m = pad(d.getMonth() + 1);
    const day = pad(d.getDate());
    const h = pad(d.getHours());
    const min = pad(d.getMinutes());
    const sec = pad(d.getSeconds());
    return `${y}-${m}-${day}T${h}:${min}:${sec}`;
  }

  function toGermanDateTimeString(d: Date): string {
    const y = d.getFullYear();
    const m = pad(d.getMonth() + 1);
    const day = pad(d.getDate());
    const h = pad(d.getHours());
    const min = pad(d.getMinutes());
    const sec = pad(d.getSeconds());
    return `${day}.${m}.${y} ${h}:${min}:${sec}`;
  }

  function startStopwatch(startTime: Date) {
    clearInterval(stopwatchInterval);

    const update = () => {
      const now = new Date();
      const diff = now.getTime() - startTime.getTime();

      if (diff < 0) {
        elapsedTimeElement.textContent = '00:00:00';
        return;
      }

      const totalSeconds = Math.floor(diff / 1000);
      const hours = Math.floor(totalSeconds / 3600);
      const minutes = Math.floor((totalSeconds % 3600) / 60);
      const seconds = totalSeconds % 60;

      elapsedTimeElement.textContent = `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
    };

    update();
    stopwatchInterval = window.setInterval(update, 1000);
  }

  function updateAll(date: Date) {
    functionalInput.value = toLocalISOString(date);
    displayInput.value = toGermanDateTimeString(date);
    startStopwatch(date);
    updateReportingDeadlines();
  }

  displayInput.addEventListener('click', () => {
    try {
      functionalInput.showPicker();
    } catch (error) {
      console.error("Browser unterstützt 'showPicker()' nicht oder es ist ein Fehler aufgetreten.", error);
    }
  });

  functionalInput.addEventListener('input', () => {
    const newDate = new Date(functionalInput.value);
    if (!isNaN(newDate.getTime())) {
      updateAll(newDate);
    }
  });

  updateAll(new Date());
}

document.addEventListener('DOMContentLoaded', () => {
  // Der Timer wird bereits in der `hydrate`-Funktion initialisiert.
});
