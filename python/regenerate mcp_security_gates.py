#!/usr/bin/env python3

"""
mcp_security_gates.py

Purpose:
Basic due-diligence checks for the MCP security architecture.

This is not a vulnerability scanner.
This validates that expected security controls exist.

Checks:
- MCP namespaces exist
- MCP server deployment exists
- mTLS gateway deployment exists
- Service accounts are not default
- Gateway service account does not mount Kubernetes token
- Containers are not privileged
- Containers run as non-root
- Containers use read-only root filesystem
- Resource limits exist
- Images avoid :latest
- NetworkPolicies exist
- TLS secrets exist
- OPA/Gatekeeper policies appear present
- RBAC bindings exist
"""

import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from kubernetes import client, config
from kubernetes.client.rest import ApiException


EXPECTED_NAMESPACES = [
    "mcp",
    "mcp-gateway",
    "ai-governance",
]

EXPECTED_DEPLOYMENTS = [
    {"name": "mcp-server", "namespace": "mcp"},
    {"name": "mcp-gateway", "namespace": "mcp-gateway"},
]

EXPECTED_TLS_SECRETS = [
    {"name": "mcp-server-tls", "namespace": "mcp-gateway"},
    {"name": "mcp-client-ca", "namespace": "mcp-gateway"},
]

EXPECTED_NETWORK_POLICY_NAMESPACES = [
    "mcp",
    "mcp-gateway",
    "ai-governance",
]

GATEWAY_SERVICE_ACCOUNT = {
    "name": "mcp-gateway-sa",
    "namespace": "mcp-gateway",
}


results: List[Dict[str, Any]] = []


def load_kube_config() -> None:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


def emit(check: str, status: str, details: str, severity: str = "info") -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "check": check,
        "status": status,
        "severity": severity,
        "details": details,
    }
    results.append(record)
    print(json.dumps(record))


def pass_check(check: str, details: str) -> None:
    emit(check, "PASS", details, "info")


def fail_check(check: str, details: str, severity: str = "high") -> None:
    emit(check, "FAIL", details, severity)


def warn_check(check: str, details: str) -> None:
    emit(check, "WARN", details, "medium")


def check_namespaces(v1: client.CoreV1Api) -> None:
    existing = {ns.metadata.name for ns in v1.list_namespace().items}

    for namespace in EXPECTED_NAMESPACES:
        if namespace in existing:
            pass_check("namespace_exists", f"Namespace exists: {namespace}")
        else:
            fail_check("namespace_exists", f"Missing namespace: {namespace}")


def get_deployment(
    apps_v1: client.AppsV1Api,
    namespace: str,
    name: str,
) -> Optional[Any]:
    try:
        return apps_v1.read_namespaced_deployment(name=name, namespace=namespace)
    except ApiException as exc:
        if exc.status == 404:
            return None
        raise


def check_expected_deployments(apps_v1: client.AppsV1Api) -> None:
    for item in EXPECTED_DEPLOYMENTS:
        deploy = get_deployment(apps_v1, item["namespace"], item["name"])

        if deploy:
            pass_check(
                "deployment_exists",
                f"Deployment exists: {item['namespace']}/{item['name']}",
            )
        else:
            fail_check(
                "deployment_exists",
                f"Missing deployment: {item['namespace']}/{item['name']}",
            )


def check_service_accounts(apps_v1: client.AppsV1Api) -> None:
    for item in EXPECTED_DEPLOYMENTS:
        deploy = get_deployment(apps_v1, item["namespace"], item["name"])
        if not deploy:
            continue

        pod_spec = deploy.spec.template.spec
        sa_name = pod_spec.service_account_name

        if not sa_name or sa_name == "default":
            fail_check(
                "service_account",
                f"{item['namespace']}/{item['name']} uses default service account",
            )
        else:
            pass_check(
                "service_account",
                f"{item['namespace']}/{item['name']} uses service account: {sa_name}",
            )


def check_gateway_sa_token(v1: client.CoreV1Api) -> None:
    try:
        sa = v1.read_namespaced_service_account(
            name=GATEWAY_SERVICE_ACCOUNT["name"],
            namespace=GATEWAY_SERVICE_ACCOUNT["namespace"],
        )
    except ApiException as exc:
        if exc.status == 404:
            fail_check(
                "gateway_service_account",
                "mcp-gateway-sa does not exist",
            )
            return
        raise

    if sa.automount_service_account_token is False:
        pass_check(
            "gateway_service_account_token",
            "mcp-gateway-sa has automountServiceAccountToken=false",
        )
    else:
        warn_check(
            "gateway_service_account_token",
            "mcp-gateway-sa should set automountServiceAccountToken=false",
        )


def iter_containers(deploy: Any) -> List[Any]:
    containers = list(deploy.spec.template.spec.containers or [])
    init_containers = list(deploy.spec.template.spec.init_containers or [])
    return containers + init_containers


def check_container_security(apps_v1: client.AppsV1Api) -> None:
    for item in EXPECTED_DEPLOYMENTS:
        deploy = get_deployment(apps_v1, item["namespace"], item["name"])
        if not deploy:
            continue

        for container in iter_containers(deploy):
            ref = f"{item['namespace']}/{item['name']}/{container.name}"
            sc = container.security_context

            if sc and sc.privileged:
                fail_check("privileged_container", f"{ref} is privileged")
            else:
                pass_check("privileged_container", f"{ref} is not privileged")

            if sc and sc.run_as_non_root is True:
                pass_check("run_as_non_root", f"{ref} runs as non-root")
            else:
                warn_check("run_as_non_root", f"{ref} should set runAsNonRoot=true")

            if sc and sc.read_only_root_filesystem is True:
                pass_check(
                    "read_only_root_filesystem",
                    f"{ref} has readOnlyRootFilesystem=true",
                )
            else:
                warn_check(
                    "read_only_root_filesystem",
                    f"{ref} should set readOnlyRootFilesystem=true",
                )

            if sc and sc.allow_privilege_escalation is False:
                pass_check(
                    "allow_privilege_escalation",
                    f"{ref} has allowPrivilegeEscalation=false",
                )
            else:
                warn_check(
                    "allow_privilege_escalation",
                    f"{ref} should set allowPrivilegeEscalation=false",
                )


def check_resource_limits(apps_v1: client.AppsV1Api) -> None:
    for item in EXPECTED_DEPLOYMENTS:
        deploy = get_deployment(apps_v1, item["namespace"], item["name"])
        if not deploy:
            continue

        for container in iter_containers(deploy):
            ref = f"{item['namespace']}/{item['name']}/{container.name}"
            resources = container.resources

            if resources and resources.requests:
                pass_check("resource_requests", f"{ref} has resource requests")
            else:
                warn_check("resource_requests", f"{ref} missing resource requests")

            if resources and resources.limits:
                pass_check("resource_limits", f"{ref} has resource limits")
            else:
                warn_check("resource_limits", f"{ref} missing resource limits")


def check_image_tags(apps_v1: client.AppsV1Api) -> None:
    for item in EXPECTED_DEPLOYMENTS:
        deploy = get_deployment(apps_v1, item["namespace"], item["name"])
        if not deploy:
            continue

        for container in iter_containers(deploy):
            image = container.image or ""
            ref = f"{item['namespace']}/{item['name']}/{container.name}"

            if image.endswith(":latest") or ":" not in image:
                warn_check("image_tag", f"{ref} image should be pinned: {image}")
            else:
                pass_check("image_tag", f"{ref} image appears pinned: {image}")


def check_network_policies(networking_v1: client.NetworkingV1Api) -> None:
    for namespace in EXPECTED_NETWORK_POLICY_NAMESPACES:
        try:
            policies = networking_v1.list_namespaced_network_policy(namespace)
        except ApiException as exc:
            if exc.status == 404:
                fail_check("network_policy", f"Namespace missing: {namespace}")
                continue
            raise

        if policies.items:
            pass_check(
                "network_policy",
                f"{namespace} has {len(policies.items)} NetworkPolicy object(s)",
            )
        else:
            warn_check(
                "network_policy",
                f"{namespace} has no NetworkPolicy objects",
            )


def check_tls_secrets(v1: client.CoreV1Api) -> None:
    for item in EXPECTED_TLS_SECRETS:
        try:
            secret = v1.read_namespaced_secret(
                name=item["name"],
                namespace=item["namespace"],
            )
        except ApiException as exc:
            if exc.status == 404:
                fail_check(
                    "tls_secret",
                    f"Missing secret: {item['namespace']}/{item['name']}",
                )
                continue
            raise

        if item["name"] == "mcp-server-tls":
            if secret.type == "kubernetes.io/tls":
                pass_check(
                    "tls_secret",
                    f"TLS secret exists: {item['namespace']}/{item['name']}",
                )
            else:
                warn_check(
                    "tls_secret",
                    f"Secret exists but is not kubernetes.io/tls: {item['namespace']}/{item['name']}",
                )
        else:
            if secret.data and "ca.crt" in secret.data:
                pass_check(
                    "client_ca_secret",
                    f"Client CA secret contains ca.crt: {item['namespace']}/{item['name']}",
                )
            else:
                fail_check(
                    "client_ca_secret",
                    f"Client CA secret missing ca.crt: {item['namespace']}/{item['name']}",
                )


def check_rbac(
    rbac_v1: client.RbacAuthorizationV1Api,
) -> None:
    namespaces = ["mcp", "mcp-gateway", "ai-governance"]

    for namespace in namespaces:
        try:
            roles = rbac_v1.list_namespaced_role(namespace)
            rolebindings = rbac_v1.list_namespaced_role_binding(namespace)
        except ApiException as exc:
            if exc.status == 404:
                continue
            raise

        if roles.items:
            pass_check("rbac_roles", f"{namespace} has {len(roles.items)} Role object(s)")
        else:
            warn_check("rbac_roles", f"{namespace} has no Role objects")

        if rolebindings.items:
            pass_check(
                "rbac_rolebindings",
                f"{namespace} has {len(rolebindings.items)} RoleBinding object(s)",
            )
        else:
            warn_check(
                "rbac_rolebindings",
                f"{namespace} has no RoleBinding objects",
            )


def check_gatekeeper_policies(custom_api: client.CustomObjectsApi) -> None:
    """
    Best-effort check.

    Gatekeeper ConstraintTemplates are cluster-scoped custom resources.
    If Gatekeeper is not installed or permissions are missing, this reports WARN.
    """

    try:
        templates = custom_api.list_cluster_custom_object(
            group="templates.gatekeeper.sh",
            version="v1",
            plural="constrainttemplates",
        )
    except ApiException as exc:
        warn_check(
            "opa_gatekeeper",
            f"Could not list Gatekeeper ConstraintTemplates: HTTP {exc.status}",
        )
        return

    count = len(templates.get("items", []))

    if count > 0:
        pass_check(
            "opa_gatekeeper",
            f"Gatekeeper ConstraintTemplates found: {count}",
        )
    else:
        warn_check(
            "opa_gatekeeper",
            "No Gatekeeper ConstraintTemplates found",
        )


def summarize() -> int:
    fail_count = sum(1 for r in results if r["status"] == "FAIL")
    warn_count = sum(1 for r in results if r["status"] == "WARN")
    pass_count = sum(1 for r in results if r["status"] == "PASS")

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "pass": pass_count,
            "warn": warn_count,
            "fail": fail_count,
        },
        "overall_status": "FAIL" if fail_count else "PASS_WITH_WARNINGS" if warn_count else "PASS",
    }

    print("\n=== MCP SECURITY GATES SUMMARY ===")
    print(json.dumps(summary, indent=2))

    return 1 if fail_count else 0


def main() -> int:
    load_kube_config()

    v1 = client.CoreV1Api()
    apps_v1 = client.AppsV1Api()
    networking_v1 = client.NetworkingV1Api()
    rbac_v1 = client.RbacAuthorizationV1Api()
    custom_api = client.CustomObjectsApi()

    print("\n=== MCP SECURITY GATES ===\n")

    check_namespaces(v1)
    check_expected_deployments(apps_v1)
    check_service_accounts(apps_v1)
    check_gateway_sa_token(v1)
    check_container_security(apps_v1)
    check_resource_limits(apps_v1)
    check_image_tags(apps_v1)
    check_network_policies(networking_v1)
    check_tls_secrets(v1)
    check_rbac(rbac_v1)
    check_gatekeeper_policies(custom_api)

    return summarize()


if __name__ == "__main__":
    sys.exit(main())
