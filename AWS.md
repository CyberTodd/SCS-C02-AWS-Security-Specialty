# AWS Security SCS-C02 Certification Services
#### Management and Governance:
- AWS CloudTrail
	- Tracks and logs API calls made on AWS, providing detailed logs of account activity for auditing and compliance.
- Amazon CloudWatch
	- Monitors and manages cloud resources, providing real-time logs, metrics, and alarms to track system performance and health.
- AWS Config
	- Tracks AWS resource configurations and changes, helping with compliance auditing, security analysis, and change management.
- AWS Organizations
	- Manages and organizes multiple AWS accounts, enabling consolidated billing and governance.
- AWS Systems Manager
	- Provides operational insights, automation, and patch management for AWS resources.
- AWS Trusted Advisor
	- Offers best practice recommendations for optimizing AWS resources in terms of cost, performance, security, and fault tolerance.

#### Networking and Content Delivery:
- Amazon VPC - Virtual Private Cloud
	- Creates isolated networks in AWS to control resource communication, security, and IP address management.
- Network Access Analyzer
	- Assesses and analyzes network configurations to help identify unintended access to resources in VPCs.
- Network ACLs - Access Control List
	- Acts as a stateless firewall for controlling inbound and outbound traffic at the subnet level in a VPC.
- Security groups
	- A stateful firewall that controls inbound and outbound traffic for EC2 instances and other resources in a VPC.
- VPC endpoints
	- Provides private connections between a VPC and supported AWS services, without the need for an internet gateway or NAT.

#### Security, Identity, and Compliance:
- AWS Audit Manager
	- Automates audit evidence collection, helping organizations prepare for audits and ensuring compliance with various standards.
- AWS Certificate Manager (ACM)
	- Manages and provisions SSL/TLS certificates for encrypting network traffic.
- AWS CloudHSM
	- Provides hardware-based key storage for managing cryptographic operations and sensitive data.
- Amazon Detective
	- Analyzes and visualizes AWS CloudTrail logs and VPC Flow Logs to identify potential security issues.
- AWS Directory Service
	- Manages Microsoft Active Directory or provides directory services to AWS applications.
- AWS Firewall Manager
	- Centralizes the management of AWS WAF and AWS Shield for protection against common web threats across multiple accounts.
- Amazon GuardDuty
	- **AWS GuardDuty** continuously monitors your AWS environment for malicious or unauthorized behavior by analyzing API calls, VPC flow logs, and DNS logs.
- AWS IAM Identity Center (AWS Single Sign-On)
	- Provides centralized identity management and Single Sign-On (SSO) access to AWS resources and third-party apps.
- AWS Identity and Access Management (IAM)
	- Manages access and permissions for users and resources, ensuring secure access control.
- Amazon Inspector
	- Automated security assessment service that identifies vulnerabilities in AWS-hosted applications.
- AWS Key Management Service (AWS KMS)
	- Manages and controls encryption keys for AWS services and applications.
- Amazon Macie
	- Uses machine learning to discover, classify, and protect sensitive data, such as personally identifiable information (PII).
- AWS Network Firewall
	- A managed firewall service that provides fine-grained traffic filtering for VPCs.
- AWS Security Hub
	- Centralizes security findings and recommendations from various AWS services and third-party tools for better security management.
- AWS Shield
	- Provides protection against DDoS attacks, offering both standard (free) and advanced protection (paid).
- AWS WAF
	- Protects applications from common web exploits and bots by filtering and monitoring HTTP/HTTPS requests.

---

# Service Features in Detail

### 🛡 **AWS Identity and Access Management (IAM)**

- **Least Privilege**: Assign only the permissions needed.
    
- **MFA Enforcement**: Deny actions unless `aws:MultiFactorAuthPresent` is true.
    
- **Policy Conditions**: Enforce HTTPS (`aws:SecureTransport`) or encryption usage.
    
- **Resource-Level Permissions**: Supported in many services (e.g., S3), **not** in RDS.

### IAM Roles 

- IAM roles have **temporary credentials** (STS tokens), unlike long-lived IAM users with access keys.
- You can **limit session duration** (as short as 15 minutes) and even enforce **MFA at assume-role time**.
- If credentials are compromised, the **short lifetime greatly reduces blast radius**.

### IAM Policies

- They control access to KMS keys

### Security Groups

- Security Groups are stateful, meaning that if you allow inbound traffic, the return is automatically allowed
- It's best practice to explicitly define both inbound and outbound rules for better control
- Default security groups may allow all outbound traffic, but you should adjust them as needed to minimize risks

---

### 🔐 **AWS Key Management Service (KMS)**

- **CMKs (Customer Managed Keys)**: Required for strict compliance and control.
    
- **Key Rotation**: Automatically rotate keys annually.
    
- **Integrated With**: S3, RDS, EBS, Lambda, Secrets Manager, etc.
- SSE-KMS supports specifying a cross-account CMK ARN
- KMS key policies control access to the KMS key itself and take precedence over IAM policies
- To ensure **only a specific IAM role** can use the key for encryption and decryption, you need to explicitly **allow access** to that role in the **key policy**

### Secrets Manager Resource Policies

- Are the primary way to limit access to a specific principal (like a Lambda IAM role)
- Enforces principle of least privilege
- Strong protection from human access

---

### 📁 **Amazon S3**

- **Encryption at Rest**:
    
    - **SSE-S3**: Amazon-managed keys
        
    - **SSE-KMS**: Use with CMKs for compliance
        
- **Block Public Access**: Must-have for securing buckets
    
- **Bucket Policies**: Enforce HTTPS, MFA, encryption
- S3 Server Access Logging logs who accessed what, when, and from where    
- **CloudTrail Data Events**: Enables access auditing
- S3 Object Lock - WORM (Write Once - Read Many) protection also prevents deletion or overwrite of objects even by root/ admin - also is perfect for compliance frameworks

---

### 🧠 **AWS Secrets Manager**

- **Automatic Rotation**: Built-in support for RDS, Aurora, Redshift, etc.
    
- **Fine-grained IAM Access**
    
- **KMS Integration**: Encrypt secrets with CMKs
    
- **CloudFormation Support**: Via **dynamic references**
    
- **Logging Access**: Through **CloudTrail**
    

---

### 🧾 **AWS Systems Manager (SSM) Parameter Store**

- **SecureString** type supports encryption with KMS
    
- **No native rotation** unless custom setup is used
    
- Can be referenced in CloudFormation, but lacks built-in rotation
    

---

### 📜 **AWS CloudTrail**

- **Logs all API activity** (control plane + optional data events) for auditing, storing, and extended retention
    
- **Data Events**: Needed to track access to objects in S3 or records in RDS/Secrets Manager
    
- **Compliance**: Used to retain logs for auditing and investigations

---

### 🗄 **Amazon RDS**

- **Encryption at Rest**: Use KMS with CMKs
    
- **SSL/TLS**: Encrypt data in transit
    
- **No resource-level IAM**: Control fine-grained access at the DB level (e.g., GRANTs)
    

---

### 💻 **AWS Lambda**

- **Least Privilege Role Per Function**
    
- **Secrets Access**: Should use Secrets Manager, not env vars
    
- **Encrypted Env Vars**: Still exposed to those with view access
    
- **Logging & Auditing**: CloudTrail for API activity
- Grant s3:PutObject permission to Lambda function on S3 to grant minimum necessary permissions for accessing S3 while being securely confined within a VPC

---

### 👁‍🗨 **Amazon Macie**

- **Discover/classify** PII in **S3**
    
- **Not** used for blocking access or database fields
    

---

### 🛡 **AWS Shield Advanced**

- **DDoS protection**, **not** involved in encryption or secrets
    

---

### ⚙️ **AWS CloudFormation**

- **Dynamic References**: Fetch secrets from Secrets Manager or SSM securely
    
- **Avoid plaintext secrets** in templates or source code
- Supports **automatic rotation**, **encryption with CMKs**, and **access control**.
```CloudFormation
{{resolve:secretsmanager:secret-name:SecretString:json-key::}}
```
- This solution is **purpose-built**, secure, and integrates directly with CloudFormation.

### API Gateway

- **Mutual TLS (mTLS)** ensures that **only known clients** with **valid certificates** can connect (strong client authentication)
- **Lambda authorizers** enable **custom auth logic**, potentially using **tokens**, IP checks, org identity, etc.

### NAT (Network Address Translation) Gateway

- access the internet from a private subnet
- access your network using allow-listed IP addresses
- enable communication between overlapping networks

### GuardDuty

- Detects threats: EC2 credential compromise, Port scans, malware, anomalous API calls
- Combine it with EventBridge + Lambda automation to quarantine EC2 instances by modifying Security Groups, NACLs (Network Access Control Lists), or stopping instances
- Alert SOC teams in real time
- Integrates with Security Hub, which acts as a centralized alert aggregator

### SCP - Service Control Policies

- Allows you to enforce org-wide guardrails
- By using **conditions like `aws:RequestTag` or `aws:ResourceTag`**, you can block access **unless a session or resource is explicitly marked** as secure (e.g., with `Environment=Production`).
- Helps **limit the blast radius** by **scoping where and when credentials can be used**.
- **SCPs apply even if a user has full IAM permissions** — so they’re excellent for protecting against credential misuse across accounts.

### VPC Peering
- Allows you to securely connect two VPCs and route traffic between them, without going through the public internet
- This is ideal for communication between different layers of your architecture, such as web and database tiers, without exposing them to public access
- It provides a private, high-speed, and secure connection between subnets in different VPCs or within the same VPC


---
## 🔐 **Identity & Access Management (IAM, SSO, STS)**

|**Keyword**|**Service**|**Why It's Used**|
|---|---|---|
|Cross-account access|IAM roles + Resource/Key Policies|Enables secure access across AWS accounts|
|Temporary credentials|AWS STS|Used for federated identity or short-lived permissions|
|Federated users|IAM + AWS SSO|Access from external IdPs (AD, Azure AD, Okta)|
|External identity provider|AWS SSO or Cognito|Auth via SAML, OIDC, SSO|
|AssumeRole|IAM + STS|Key action to switch context across accounts|
|Least privilege|IAM policies / SCPs|Minimize risk by limiting permissions|
|Expiring access|STS / SSO sessions|Temporary credentials with auto-expiry|
|Directory integration|AWS SSO / AD Connector / AWS Managed Microsoft AD|For on-prem AD or cloud directory use|
|Identity federation|IAM + SSO + STS|Use corporate credentials with AWS|
|Auditable access|CloudTrail + SSO logs + IAM Access Analyzer|For compliance and traceability|

---

## 🛡️ **KMS & Encryption**

|**Keyword**|**Service**|**Why It's Used**|
|---|---|---|
|CMK / Customer-managed key|AWS KMS|Full control over key usage and access|
|Cross-account encryption|KMS with key policy + IAM|Secure data sharing across accounts|
|Key rotation|KMS|Automatic annual key renewal for CMKs|
|SSE-KMS / SSE-S3|KMS / S3|Server-side encryption with customer-managed or AWS-managed keys|
|Enforce encryption|SCP + S3 bucket policy + KMS|Ensure encryption on storage and services|
|Key policy|KMS|Grants use/decrypt permissions on CMKs|
|Decrypt access|KMS + IAM + Key policy|Critical for cross-account decryption of S3, RDS, etc.|
|Compliance|CMK + CloudTrail + Object Lock|For regulations like PCI-DSS, HIPAA|

---

## 📦 **S3 Security & Logging**

|**Keyword**|**Service**|**Why It's Used**|
|---|---|---|
|Immutable logs|S3 Object Lock (Compliance Mode)|WORM storage for regulatory compliance|
|Tamper-proof|S3 + Object Lock + CloudTrail validation|For evidential integrity|
|Log validation|CloudTrail + SHA256 + digest files|Proves no log tampering occurred|
|Access control|Bucket policy + IAM + VPC endpoint|S3 access management layers|
|Deny deletes|Bucket policy or Object Lock|Prevents accidental or malicious deletions|
|Versioning|S3|Retains object history, works with Object Lock|
|Encrypted S3|SSE-KMS|Server-side encryption with customer keys|
|Access logs|S3 server access logging / CloudTrail|For data access tracking|

---

## 🧱 **VPC Networking & Firewalls**

|**Keyword**|**Service**|**Why It's Used**|
|---|---|---|
|Private subnet|VPC|Keeps resources from direct internet access|
|NAT Gateway|VPC|Enables outbound internet without inbound access|
|Static IPs|NAT Gateway with Elastic IP|Auditing + allowlisting|
|Deep packet inspection|AWS Network Firewall|Content-aware traffic filtering|
|Central inspection|Network Firewall + custom routes|Enforce egress monitoring across workloads|
|NACL vs Security Group|VPC|NACLs = stateless, SGs = stateful|
|Internet access (no inbound)|NAT Gateway / Instance|Classic pattern for patching, etc.|
|VPC Endpoint|Interface / Gateway endpoint|Private access to AWS services, not internet|

---

## 🛡️ **Service Control Policies (SCPs)**

|**Keyword**|**Service**|**Why It's Used**|
|---|---|---|
|Prevent public IPs|SCP with condition on `ec2:AssociatePublicIpAddress`|Org-wide enforcement of private workloads|
|Force encryption|SCP with condition on `s3:x-amz-server-side-encryption`|Data protection policy control|
|Deny services/regions|SCP|Lockdown org-wide usage patterns|
|Organizational guardrails|SCP|Cannot be overridden at account level|

---

## 📈 **Logging, Auditing & Monitoring**

|**Keyword**|**Service**|**Why It's Used**|
|---|---|---|
|Immutable logs|S3 Object Lock + CloudTrail|Regulatory logging|
|Real-time monitoring|CloudWatch Logs / Metrics / Alarms|Operational visibility|
|Audit access|CloudTrail + Access Analyzer|Trace who did what, where, and when|
|Centralized logging|CloudTrail org trails to S3|Audit all accounts centrally|
|Cross-region replication|S3 CRR|Backup logs securely in another region|

---

## 🧠 **Security Architecture Patterns**

|**Pattern / Phrase**|**Solution**|**Why It's Chosen**|
|---|---|---|
|Inspect traffic before egress|AWS Network Firewall|Full visibility + enforcement|
|Prevent internet exposure|Private subnet + NAT Gateway|Outbound-only architecture|
|External identity provider access|AWS SSO + SAML or OIDC|Partner logins, no IAM users needed|
|Secure cross-account data access|KMS + IAM + Key policy|Fine-grained, auditable, encrypted sharing|
|Least privilege, org-wide|SCP + IAM boundaries|Principle of least privilege at scale|

---

## ✅ Most Tested Use Cases

| **Scenario**                        | **Correct Service Combo**          |
| ----------------------------------- | ---------------------------------- |
| Cross-account encrypted S3 access   | KMS CMK + Key policy + IAM         |
| Immutable CloudTrail logs           | S3 Object Lock (Compliance mode)   |
| Deny creation of public EC2 IPs     | SCP + ec2:AssociatePublicIpAddress |
| SSO to AWS with Azure AD            | AWS SSO + External IdP (SAML 2.0)  |
| Inspect outbound VPC traffic        | AWS Network Firewall + NAT         |
| Internet access from private subnet | NAT Gateway + Route table          |
| Audit user actions                  | CloudTrail + CloudWatch + S3       |

