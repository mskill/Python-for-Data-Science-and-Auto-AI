## COURSE SYLLABUS
### Course : Fundamentals of Enterprise Security

#### MODULE 1 – UNDERSTANDING THE CYBERSECURITY LANDSCAPE
The current cybersecurity landscape
The evolution of attacks
Understanding “Assume Compromise”
Examples of compromises
Evolution of Attacks

#### MODULE 2 – RED TEAM: PENETRATION, LATERAL MOVEMENT, ESCALATION, AND EXFILTRATION
Red Team versus Blue Team
Red Team kill chain
Beachhead
Lateral movement
Privileged escalation
Execution of attacker’s mission
Demonstration of Pass the hash attack
Demonstration of Golden Ticket Attack

#### MODULE 3 – BLUE TEAM: DETECTION, INVESTIGATION, RESPONSE, AND MITIGATION
Gathering baseline data
Detecting Intrusion
Alerting
Investigation
Planning a Response
The Blue Team kill chain
Restricting privilege escalation
Demonstration of Device Guard
Demonstration of Credential Guard
OMS/Azure Security Center
On-premises network security
Restrict lateral movement
Demonstrations of LAPS
Attack detection

#### MODULE 4 – BEYOND THE BREACH
Developing a Baseline Security Posture
Information Classification
Change Tracking
Monitoring
Reporting
Organizational preparations
Processes
CIA Triad
Developing a strategic roadmap
Microsoft Security Response Center Exploitability Index

### Course : Threat Detection: Planning for a Secure Enterprise

#### Module 1 – Introduction to threat detection as part of the defense in-depth strategy
An overview of the modern cyber threat landscape
Integrating pre-breach and post-breach approaches to mitigate cyber threats
Comparing signature-based and behavioural/heuristic detection methods
Combating threat persistence

#### Module 2 – Detecting threats in on-premises environments
Windows Defender Advanced Threat Protection
Microsoft Advanced Threat Analytics
Microsoft Enterprise Threat Detection
Microsoft Security Risk Detection
Antimalware Scan Interface
Logging and Auditing
Threat detection tools

#### Module 3 – Detecting threats in hybrid and cloud environments
Office 365 Advanced Threat Protection
Office 365 Cloud App Security and Microsoft Cloud App Security
Azure Advanced Threat Detection
Azure Active Directory Identity Protection
Azure Active Directory Identity Threat Detection
Microsoft Operations Management Suite (OMS)
Azure Security Center
Advanced Threat Detection Features - Other Azure Services
Third-party ATD capabilities through Azure Marketplace
Azure Logging and Auditing
Microsoft 365

#### Module 4 – Analyzing threat detection solutions in action
Detecting persistent threats by using Windows Defender Advanced Threat Protection and Advanced Threat Analytics
Enterprise Threat Detection behavioral monitoring

### Course  - Planning a Security Incident Response

#### Module 1
Introduction
What is threat modelling?
Key Takeaways from Cyberattacks
Cyber Threat modeling
NIST Cybersecurity Framework
Prepare for a security incident
Phases of a major response
Recovery preparations
Critical success factors

#### Module 2
Incident Response Policy, Plan, and Procedure Creation
Creation of a CSIRT
List for developing a CSIRT
Team duties
Team preparations
Establishing team roles
CSIRT communications
Recovering your systems
Key Takeaways

#### Module 3
The security incident report
Practice walking through a security incident report
Next steps

### Course  - PowerShell Security Best Practices - Introduction

*One module will be released each week, with a moderated discussion board. Students will complete hands-on labs in an online virtual environment. A Verified Certificate is available after obtaining 70% on the course graded events.*

#### Module 1 – PowerShell Fundamentals
Windows PowerShell Architecture
Windows PowerShell editions and versions
Running Windows PowerShell

#### Module 2 – PowerShell Operational Security
Managing local script execution with Windows PowerShell Execution Policy
Managing remote execution capabilities of Windows PowerShell
Constrained endpoints
Language Mode
Anti-Malware Scan Interface (AMSI)

#### Module 3 – Implementing Windows PowerShell-based Security
Widows PowerShell DSC
Just Enough Administration (JEA)
Windows PowerShell Auditing and Logging

#### Module 4 – Windows PowerShell-based Exploits and their Mitigation
Windows PowerShell-based attacks
Windows PowerShell-based security tools
Summary of Windows PowerShell-based security-related technologies

#### Module 5 - Course Completion
Graded Lab
Final Exam
Post Course Survey

### Course - Microsoft INF523x – Managing Identity

#### Module 1 – Identify as a Service (IaaS), the new Control Plane


Securing Privileged Access (SPA).

oSecuring Privileged Access Roadmap: Stage 1

oSecuring Privileged Access Roadmap: Stage 2

oSecuring Privileged Access Roadmap: Stage 3

Key issues that require better identity capabilities

Topics: Identity as a Service. Identity management, provisioning and deprovisioning, role management, and authentication, Software as a Service (SaaS), Single Sign On (SSO), Bring your own Identify (BYOI), Confidentiality, Integrity and Availability make up the CIA Triad, User identities from multiple repositories, built in two-factor authentication, Account Lockdown, and an overview of Credential Guard, Microsoft Passport, Windows Hello for Business

Demonstrations: Show how an attacker can use common tools to acquire Administrative Credentials

#### Module 2 – Securing Active Directory (AD)

Key Training Points:

Avenues to Compromise

Reducing the Active Directory Attack Surface

Monitoring Active Directory

Planning for a Compromise

Maintaining a More Secure Environment

Topics: Gaps in Antivirus and Antimalware Deployments; incomplete patching for Microsoft and non-Microsoft OS & apps; misconfigurations; outdated OS and apps. Forest trust relationships, nonmigratory approach to populate a pristine forest, segregation of legacy OS & applications, domain controller management; reduction to a minimum of Domain Admin accounts, Enterprise Admins, built-in Admins; eliminate permanent membership in escalated privilege, Privileged Access Workstations (PAW), Identifying and securing critical assets; eliminate SID history and Token Bloat; Isolating Legacy systems and applications; Authentication Mechanism Assurance; review the Default Domain policy.

#### Module 3 – Azure Active Directory (AAD)

Key Training Points:

Identity Federation and access solutions

Azure Active Directory Identity Protection

Enable Single Sign-On (SSO)

Deploy password management

Enforce multi-factor authentication (MFA) for users

Use role-based access control (RBAC)

Azure Key Vault

Azure Application Proxy

Azure AD Connect

Topics: AAD account; Active Directory Federation Services (AD FS); Azure Rights Management; Web Application Proxy; Claims; Certificates, Azure Multi-Factor Authentication; encrypted data at rest and in motion; Key Vault service; SSO, Azure AD Connect

Demonstrations: AAD Identity Protection, SSO, MFA, Azure Key Vault, Azure RBAC

#### Module 4 – Authentication and Authorization in Active Directory

Key Training Points:

Kerberos + Privilege Attribute Certification (PAC)

Security Support Provider Interface Overview

Sign in Sequence for Domain Joined Clients

Topics: Kerberos v5/AD; AES 256, NTLM encryption; How Kerberos / AD works, i.e. Service Tickets, Ticket Granting Ticket (TGT) Key Distribution Center (KDC), Generic Security Service (GSS) messages, one-way hash, Public Key two-factor authentication; PAC + Users access token, Login Architecture, i.e., Kerberos client, TGTs, KDC, cache of ticket; Interactive Logon Protocols, Interactive Logon Process and Interactions, Network Ports used; Winlogon tasks.

Course Lab: AD Privileged Access Management (PAM) and Just In Time Administration (JIT)

You have a Windows Server 2016 Active Directory single domain forest named corp.contoso.com. You plan to implement Privileged Access Management and Just In Time Administration to provide maximum control over privileged access in your domain. You will use for this purpose capabilities offered by Microsoft Identity Manager (MIM). The implementation will use MIM 2016 SP1.

Objectives

After completing this lab, students will be able to:

Implement PAM infrastructure

Implement and verify functionality of PAM users, groups, and roles

### Course : Securing Data in Azure and SQL Server.

#### Module 1: Authenticating Users
Authenticating Connections to SQL Server
Authorizing Logins to Connect to Databases
Lab

#### Module 2: Authorizing Users to Access Resources
Working with Server Roles
Working with Database Roles
Authorizing User Access to Objects
Lab

#### Module 3: Auditing Access
Options for Auditing Data Access in SQL Server
Implementing SQL Server Audit
Lab

#### Module 4: Encrypting Data
Protecting Data with Encryption
Lab

### Course : Windows 10 Security - Introduction

#### Module 1: Authenticating Users
Authenticating Connections to SQL Server
Authorizing Logins to Connect to Databases
Lab

#### Module 2: Authorizing Users to Access Resources
Working with Server Roles
Working with Database Roles
Authorizing User Access to Objects
Lab

#### Module 3: Auditing Access
Options for Auditing Data Access in SQL Server
Implementing SQL Server Audit
Lab

#### Module 4: Encrypting Data
Protecting Data with Encryption
Lab

### Course -Understanding and Enabling Windows Server 2016 Security Features
#### Module 1 – Reduce Attack Surface
Minimize footprint with Server Core deployment
Understand attack surface reduction
Manage service accounts
Configure group managed service accounts
Configure Windows Server 2016 for secure boot
Use device guard to limit execution of untrusted code

#### Module 2 - Secure Administration
Understand the need to protect privileged accounts
Credential guard
Remote credential guard
Restricting administrator access
Just In Time Administration
Just Enough Administration

#### Module 3 – Isolate Workloads with Containers
Isolating workloads in containers
Understand container types
Manage containers with Docker
Understand Hyper-V containers
Understand Windows Server containers

#### Module 4 – Secure Virtualization Infrastructure
Understand guarded fabrics and threats they address
Admin-trusted and tpm-trusted attestation
Host guardian service
Encrypted and shielded VMs

#### Module 5 - Course Completiom
Final Exam

### Course - Microsoft Azure Security Services
#### Module 1 – Azure Security Architecture
Azure security architecture overview
Azure Networking Security
Network Security Groups
Secure Remote Access
Monitoring and threat detection
Azure Reference architectures
Secure Azure Virtual Machine Templates

#### Module 2 – Azure Security and Operations Management
The cloud service models
Shared responsibilities for security
The features of Azure Security Center
Azure Security Center case study
Non-graded lab using Azure Security Center
Azure Backup
Azure Log Analytics

#### Module 3 – Azure Security Services
Azure Application Gateway
Web Application Firewall adds to the security posture
Distributed Denial of Services (DDoS) attacks in Azure
Azure Disk & Storage Encryption
Azure SQL Encryption

#### Module 4 – Data Management for Apple, Android, Windows Device
Microsoft Intune for Windows, iOS, and Android devices
Device Health Attestation
Mobile Device Management (MDM)
Mobile Application Management (MAM)
Data governance with GDPR
Security aspects of AutoPilot
#### Module 5 - Course Completiom
Final Exam
