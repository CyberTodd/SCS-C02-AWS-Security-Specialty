# AWS Security SCS-C02 Certification Services

# Service Features in Detail

### 🛡 **AWS Identity and Access Management (IAM)**

- **Least Privilege**: Assign only the permissions needed.
    
- **MFA Enforcement**: Deny actions unless `aws:MultiFactorAuthPresent` is true.
    
- **Policy Conditions**: Enforce HTTPS (`aws:SecureTransport`) or encryption usage.
    
- **Resource-Level Permissions**: Supported in many services (e.g., S3), **not** in RDS.
- IAM database authentication lets your app connect to RDS without passwords, using temporary credentials tied to IAM roles
- IAM service last accessed data for roles to check "when was this role last assumed?"
- IAM Access Analyzer with policy validation helps you detect overly permissive policies before they're even deployed
- a security engineer needs to block users from attaching existing unapproved security groups when launching new EC2 instances - we create a IAM policies that restrict EC2:RunInstances by resource tags
- you want to automatically detect when an IAM user is created in any of your AWS accounts and receive notifications immediately - we use EventBridge  rule on CreateUser API and notify via SNS
- if we want to ensure that temporary credentials (like STS AssumeRole) are not used beyond a specific time windows - we use aws: CurrentTime

### IAM Roles 

- IAM roles have **temporary credentials** (STS tokens), unlike long-lived IAM users with access keys.
- You can **limit session duration** (as short as 15 minutes) and even enforce **MFA at assume-role time**.
- If credentials are compromised, the **short lifetime greatly reduces blast radius**
- you want to allow an application running in AWS to assume an IAM role in another AWS account securely, but you must protect against confused deputy attacks - use an IAM role with a trust policy that requires an External ID and Configure the source account to pass the External ID
- an application needs to access as S3 bucket from an EC2 instance, the security team mandates no access keys should ever be stored on the instance - we should assign an IAM role to the EC2 instance
- a company must allow users to authenticate to AWS Management Console without creating IAM users in each account - use IAM Identity Center (AWS SSO)
- you want to ensure that API calls from on-premises servers to AWS services are authenticated and encrypted, and can be revoked instantly if compromised - we use AWS IAM Roles Anywhere with short-lived credentials
- A company uses cross-account IAM roles for developers to access staging and production environments. You need to ensure that **CloudTrail logs can’t be modified or deleted**, even by those with full admin access in the target accounts - you should store logs in a centralized account and restrict access via bucket policy

### IAM Policies

- They control access to KMS keys
- you need to ensure that all IAM users in the AWS Organization rotate their passwords every 60 days - IAM password policy

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
- SSE-KMS ensures encryption at rest, and gives fine-grained access control (who can use which keys), it's better than SSE-S3 for sensitive/ regulated data like HIPAA
- To ensure **only a specific IAM role** can use the key for encryption and decryption, you need to explicitly **allow access** to that role in the **key policy**
- When automatic key rotation occurs in AWS KMS, the alias stays the same, but the underlying key version changes
- a security team needs to monitor all AWS KMS API activity across an organization for suspicious behavior like key deletion attempts - you should use AWS Config + CloudTrail and GuardDuty + CloudTrail
- you need to enforce that all Lambda environment variables are encrypted at rest using your own KMS CMK, not the default AWS managed key - we specify KMS key in the Lambda function configuration
- we add a condition in the key policy with aws: PrincipalAccount - if we want to ensure that AWS KMS keys can only be used within a specific AWS account, even if shared with other accounts

### Secrets Manager Resource Policies

- Are the primary way to limit access to a specific principal (like a Lambda IAM role)
- Enforces principle of least privilege
- Strong protection from human access

---

### 📁 **Amazon S3**

- **Encryption at Rest**:
    
    - **SSE-S3**: Amazon-managed keys
        
    - **SSE-KMS**: Use with CMKs for compliance
        
- **S3 Block Public Access**: Must-have for securing buckets at organization level
    
- **Bucket Policies**: Enforce HTTPS, MFA, encryption
- you need to enforce that only requests from trusted AWS services (like CloudTrail or Config) can put objects into an S3 bucket used for centralized logging - we should use a bucket policy with a condition on aws:SourceArn and aws: SourceAccount
- S3 Server Access Logging logs who accessed what, when, and from where    
- **CloudTrail Data Events**: Enables access auditing
- S3 Object Lock - WORM (Write Once - Read Many) protection also prevents deletion or overwrite of objects even by root/ admin - also is perfect for compliance frameworks
- If you need to securely share access to a private S3 bucket with an external third party for a limited time without creating IAM users then use a generated pre-signed S3 URL
- S3 VPC Endpoint (Gateway type) is used when a security engineer wants to allow EC2 instances in a private subnet to access S3 buckets securely without using public IPs or NAT gateways
- S3 Object-level CloudTrail logging captures full details - who accessed the object, from what IP, at what time, what action was taken (GetObject, PutObject, etc)
- You must ensure log files stored in Amazon S3 cannot be overwritten or deleted for at least 7 years we enable S3 Object Lock in Governance mode and Compliance mode
- you want to have additional server-side encryption for a file that is already encrypted on the client side and you cannot modify application code - you use SSE-KMS
- you need to ensure that S3 bucket policies prevent any object uploads unless a specific AWS KMS key is used for server-side encryption - use s3:x-amz-server-side-encryption
- you want to restrict S3 access so that only requests coming from your VPC (via a VPC endpoint) are allowed - we use aws: SourceVpce
- you need to ensure that CloudTrail logs from all AWS accounts in your org are delivered centrally to one S3 bucket, and that no other accounts can write to that bucket - we use AWS Organizations with CloudTrail delegated administrator and on org trail
- you want to ensure S3 objects are only uploaded if they are encrypted using a specific AWS KMS key (not the default one) - we use 

---

### 🧠 **AWS Secrets Manager**

- **Automatic Rotation**: Built-in support for RDS, Aurora, Redshift, etc.
    
- **Fine-grained IAM Access**
    
- **KMS Integration**: Encrypt secrets with CMKs
    
- **CloudFormation Support**: Via **dynamic references**
    
- **Logging Access**: Through **CloudTrail**
- AWS Secrets Manager with Lambda rotation function is the best option when a security engineer must ensure that secrets (db passwords, API keys) are rotated automatically without changing the application code
- if you want to ensure that secrets (API keys) stored in AWS Secrets Manager cannot be accidentally deleted - attach a resource-based policy with Deny DeleteSecret

---

### 🧾 **AWS Systems Manager (SSM) Parameter Store**

- **SecureString** type supports encryption with KMS
    
- **No native rotation** unless custom setup is used
    
- Can be referenced in CloudFormation, but lacks built-in rotation
    

---

### 📜 **AWS CloudTrail**

- **Logs all API activity** (control plane + optional data events) for auditing, storing, and extended retention (checks who, when and which/ what action was performed)
    
- **Data Events**: Needed to track access to objects in S3 or records in RDS/Secrets Manager
    
- **Compliance**: Used to retain logs for auditing and investigations
- CloudTrail has a built-in feature to check data authenticity (file validation, uses a sha256 hash and digital signatures to detect if logs have been tampered with)
- a company enforces strict data residency (no data (even temporarily) can leave eu-west-1 and they use AWS CloudTrail) - we create an organization trail with log file validation enabled in eu-west-1

---

### 🗄 **Amazon RDS**

- **Encryption at Rest**: Use KMS with CMKs
- a company must ensure that KMS keys used for encrypting RDS snapshots cannot be used by anyone outside the security team - we create a key policy that allows only a security team IAM role 
    
- **SSL/TLS**: Encrypt data in transit
    
- **No resource-level IAM**: Control fine-grained access at the DB level (e.g., GRANTs)
- When you create RDS instance you must enable encryption at launch and specify a customer-managed CMK, once encrypted, key rotation is automatic - you cannot add encryption to an existing RDS instance - you have to start with encryption enabled

---

### 💻 **AWS Lambda**

- **Least Privilege Role Per Function**
    
- **Secrets Access**: Should use Secrets Manager, not env variables
    
- **Encrypted Env Vars**: Still exposed to those with view access
    
- **Logging & Auditing**: CloudTrail for API activity
- Grant s3:PutObject permission to Lambda function on S3 to grant minimum necessary permissions for accessing S3 while being securely confined within a VPC
- Signed tokens, short-lived, and authorized before Lambda -> that's exactly what API Gateway Lambda authorizers with JWTs are built for
- a security audit requires that all API calls made from Lambda functions in your account must be traceable to an IAM role, no hardcoded credentials allowed - you should attach an IAM role to the Lambda function
- you need to ensure that Lambda functions in a specific VPC subnet can only access DynamoDB and cannot access the internet or any other AWS service - we should configure a VPC endpoint for DynamoDB and no NAT gateway

---

### 👁‍🗨 **Amazon Macie**

- **Discover/classify** PII in **S3**
    
- **Not** used for blocking access or database fields
- you must ensure that all sensitive data uploaded to S3 from any AWS account in your organization is automatically classified and tagged, even if the bucket is misconfigured - you enable Macie with automated sensitive data discovery and use EventBridge to tag objects

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

- Threat detection: EC2 credential compromise, Port scans, malware, anomalous API calls
- Combine it with EventBridge + Lambda automation to quarantine EC2 instances by modifying Security Groups, NACLs (Network Access Control Lists), or stopping instances
- Alert SOC teams in real time
- Integrates with Security Hub, which acts as a centralized alert aggregator
- a company want to detect when someone disables GuardDuty in any account across an organization - we use CloudTrail logging and EventBridge rule
- you want to prevent users from disabling GuardDuty in any region. The most effective way to enforce this accross all accounts - use AWS Organizations SCP denying guardduty:Disables*

### SCP - Service Control Policies

- Allows you to enforce org-wide guardrails
- By using **conditions like `aws:RequestTag` or `aws:ResourceTag`**, you can block access **unless a session or resource is explicitly marked** as secure (e.g., with `Environment=Production`).
- Helps **limit the blast radius** by **scoping where and when credentials can be used**.
- **SCPs apply even if a user has full IAM permissions** — so they’re excellent for protecting against credential misuse across accounts.

### VPC Peering

- Allows you to securely connect two VPCs and route traffic between them, without going through the public internet
- This is ideal for communication between different layers of your architecture, such as web and database tiers, without exposing them to public access
- It provides a private, high-speed, and secure connection between subnets in different VPCs or within the same VPC
- VPC endpoints with AWS PrivateLink and deny internet access via a no-NAT architecture to have access for some APIs, but data must never be sent to external IPs unintentionally
- an AWS Lambda function must retrieve a secret from AWS Secrets Manager securely. The company mandates that no secret data should ever traverse the public internet, even inside AWS - we should use VPC endpoints for Secrets Manager and place Lambda in a VPC
- you must ensure that only specific VPC endpoints can access the S3 bucket, and all other traffic must be blocked, including internet traffic and non-approved VPCs - you use VPC endpoint policies to restrict access to the S3 bucket
- If we want to configure access so that no EC2 instance, even with a public IP, can access the internet unless explicitly allowed, while still enabling instances to access internal AWS services like S3 securely, we use VPC endpoints (Gateway and Interface) and remove the Internet Gateway 


---
### 🔐 **Identity & Access Management (IAM, SSO, STS)**

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

### 🛡️ **KMS & Encryption**

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

### 📦 **S3 Security & Logging**

| **Keyword**                       | **Service**                              | **Why It's Used**                              |
| --------------------------------- | ---------------------------------------- | ---------------------------------------------- |
| Immutable logs, Unchanged Objects | S3 Object Lock (Compliance Mode)         | WORM storage for regulatory compliance         |
| Tamper-proof                      | S3 + Object Lock + CloudTrail validation | For evidential integrity                       |
| Log validation                    | CloudTrail + SHA256 + digest files       | Proves no log tampering occurred               |
| Access control                    | Bucket policy + IAM + VPC endpoint       | S3 access management layers                    |
| Deny deletes                      | Bucket policy or Object Lock             | Prevents accidental or malicious deletions     |
| Versioning                        | S3                                       | Retains object history, works with Object Lock |
| Encrypted S3                      | SSE-KMS                                  | Server-side encryption with customer keys      |
| Access logs                       | S3 server access logging / CloudTrail    | For data access tracking                       |

---

### 🧱 **VPC Networking & Firewalls**

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

### 🛡️ **Service Control Policies (SCPs)**

| **Keyword**               | **Service**                                                                                                                                                                                                                                   | **Why It's Used**                         |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| Prevent public IPs        | SCP with condition on `ec2:AssociatePublicIpAddress`                                                                                                                                                                                          | Org-wide enforcement of private workloads |
| Force encryption          | SCP with condition on `s3:x-amz-server-side-encryption` ( if you want to ensure that S3 objects are only uploaded if they are  encrypted using a specific AWS KMS key (not the default one) `s3:x-amz-server-side-encryption-aws-kms-key-id`) | Data protection policy control            |
| Deny services/regions     | SCP                                                                                                                                                                                                                                           | Lockdown org-wide usage patterns          |
| Organizational guardrails | SCP                                                                                                                                                                                                                                           | Cannot be overridden at account level     |

---

### 📈 **Logging, Auditing & Monitoring**

|**Keyword**|**Service**|**Why It's Used**|
|---|---|---|
|Immutable logs|S3 Object Lock + CloudTrail|Regulatory logging|
|Real-time monitoring|CloudWatch Logs / Metrics / Alarms|Operational visibility|
|Audit access|CloudTrail + Access Analyzer|Trace who did what, where, and when|
|Centralized logging|CloudTrail org trails to S3|Audit all accounts centrally|
|Cross-region replication|S3 CRR|Backup logs securely in another region|

---

### 🧠 **Security Architecture Patterns**

|**Pattern / Phrase**|**Solution**|**Why It's Chosen**|
|---|---|---|
|Inspect traffic before egress|AWS Network Firewall|Full visibility + enforcement|
|Prevent internet exposure|Private subnet + NAT Gateway|Outbound-only architecture|
|External identity provider access|AWS SSO + SAML or OIDC|Partner logins, no IAM users needed|
|Secure cross-account data access|KMS + IAM + Key policy|Fine-grained, auditable, encrypted sharing|
|Least privilege, org-wide|SCP + IAM boundaries|Principle of least privilege at scale|

---

### ✅ Most Tested Use Cases

| **Scenario**                        | **Correct Service Combo**          |
| ----------------------------------- | ---------------------------------- |
| Cross-account encrypted S3 access   | KMS CMK + Key policy + IAM         |
| Immutable CloudTrail logs           | S3 Object Lock (Compliance mode)   |
| Deny creation of public EC2 IPs     | SCP + ec2:AssociatePublicIpAddress |
| SSO to AWS with Azure AD            | AWS SSO + External IdP (SAML 2.0)  |
| Inspect outbound VPC traffic        | AWS Network Firewall + NAT         |
| Internet access from private subnet | NAT Gateway + Route table          |
| Audit user actions                  | CloudTrail + CloudWatch + S3       |

### AWS CloudHSM 

- Lets you generate and store encryption keys entirely outside of AWS control

CloudTrail + Service last accessed data - logs what permissions are actually used by the Lambda and the service shows which services were actually accessed by a role.

### AWS Security Hub

- AWS Security Hub integrates with AWS Config, supports managed rules, and can run org-wide via AWS Organizations, is the best choice for automated compliance and port exposure checks

### CloudWatch Events (EventBridge)

- AWS Config tracks configuration changes to resources, CloudWatch Events (EventBridge) can detect those specific changes in near real-time and triggers alerts
- Use EventBridge to capture findings and trigger a Lambda to post to Slack - to ensure that high-severity findings are sent to a central team Slack channel in near real-time

### CloudFront

- Configure the security policy on CloudFront and API Gateway to allow only TLS 1.2+

### AWS Config

- AWS Config comes with managed rules likes s3-bucket-public-read-prohibited and s3-bucket-public-write-prohibited, and can trigger SNS or EventBridge notifications the moment a bucket goes public.
- AWS Systems Manager Automation with AWS Config can be used for security governance if you want to automatically remediate noncompliant resources (auto-encrypt unencrypt EBS volumes)
- if you want to detect if access keys haven't been used in 90 days, and take automated action like disabling them - we should use AWS Config with a custom rule

### AWS Organizations

- if you want to ensure that no EC2 instances in any account can be launched without EC2 Instance Metadata Service v2 (IMDSv2) enforced - use an SCP to deny launching EC2 instances without IMDSv2

### EBS Volumes

- a company must ensure that all EBS volumes across all AWS accounts are automatically encrypted at creation time - use set default encryption in each AWS account
- your organization wants to encrypt EBS volumes using customer-managed KMS keys, but ensure that only EC2 instances in a specific VPC can attach those volumes - we use KMS key policy with aws:SourceVpce

### AWS Signature Version 4

- your organization requires that API calls to AWS services are signed and must explicitly reject any unsigned requests - use AWS Signature Version 4

### EC2

- your company mandates that no EC2 instances should ever be launched without a specific approved AMI - we should use IAM policy restricting RunInstances action based on AMI ID
- you must prevent all EC2 instances in a specific OU from launching with public IP addresses, regardless of user intent or subnet settings - you should use an SCP with condition on ec2: AssociatePublicIpAddress

### AWS CLI

- a developer needs to use the AWS CLI to temporarily assume a role with MFA and access to S3 and Lambda for 1 hour. We want the most secure and flexible way to achieve this - we should use AWS SSO with assigned permissions and default session duration

### Other 
- your company requires all AWS resources to be deployed with tags that indicate data classification (e.g. DataSensitivity=Confidential). The security team must be alerted if untagged resources are created - use AWS Config rules to evaluate resources and trigger SNS via EventBridge