"""Command-line interface for OVN-NetDiag.

Uses argparse for CLI parsing. Supports four commands:
  - diagnose    Run full network diagnostic
  - cluster-info  Show cluster overview
  - pod-info    Show detailed pod information
  - ovn-info    Show OVN state
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Sequence

from ovn_netdiag.config import RuntimeConfig
from ovn_netdiag.diagnostic_engine import DiagnosticEngine
from ovn_netdiag.logging_config import configure_logging
from ovn_netdiag.reporter import Reporter

PROG_NAME = "ovn-netdiag"
PROG_DESC = "OVN-Kubernetes Network Diagnostics Tool"
PROG_VERSION = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog=PROG_NAME,
        description=PROG_DESC,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            f"  {PROG_NAME} diagnose --namespace frontend --source frontend-pod --destination backend-pod --port 8080 --protocol tcp --mock\n"
            f"  {PROG_NAME} cluster-info --mock\n"
            f"  {PROG_NAME} pod-info --namespace frontend --pod frontend-pod --mock\n"
            f"  {PROG_NAME} ovn-info --mock\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"{PROG_NAME} {PROG_VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- diagnose ---
    diag = subparsers.add_parser(
        "diagnose",
        help="Run a full network diagnostic between two pods",
        description="Diagnose why TCP traffic between two pods is reachable, blocked, or unreachable.",
    )
    _add_common_options(diag)
    diag.add_argument("--namespace", required=True, help="Namespace of the source pod")
    diag.add_argument("--source", required=True, help="Source pod name")
    diag.add_argument("--destination", required=True, help="Destination pod name")
    diag.add_argument("--port", type=int, required=True, help="Destination port")
    diag.add_argument("--protocol", default="tcp", choices=["tcp", "udp"], help="Protocol (default: tcp)")

    # --- cluster-info ---
    ci = subparsers.add_parser(
        "cluster-info",
        help="Show cluster overview",
        description="Display an overview of the Kubernetes/OVN/OVS cluster state.",
    )
    _add_common_options(ci)

    # --- pod-info ---
    pi = subparsers.add_parser(
        "pod-info",
        help="Show detailed pod information",
        description="Display detailed information about a specific pod, including related resources.",
    )
    _add_common_options(pi)
    pi.add_argument("--namespace", required=True, help="Namespace of the pod")
    pi.add_argument("--pod", required=True, help="Pod name")

    # --- ovn-info ---
    oi = subparsers.add_parser(
        "ovn-info",
        help="Show OVN state",
        description="Display OVN Northbound/Southbound database state.",
    )
    _add_common_options(oi)

    return parser


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    """Add common options to a subparser."""
    parser.add_argument("--json", dest="json_output", action="store_true", help="Output in JSON format")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose (DEBUG) logging")
    parser.add_argument("--mock", action="store_true", help="Use mock data instead of real cluster")
    parser.add_argument("--mock-data", dest="mock_data_path", default=None, help="Path to custom mock data JSON file")
    parser.add_argument("--kubeconfig", default=None, help="Path to kubeconfig file (real mode only)")
    parser.add_argument("--timeout", type=float, default=5.0, help="General timeout in seconds (default: 5)")
    parser.add_argument("--ovn-timeout", type=float, default=10.0, help="OVN command timeout (default: 10)")
    parser.add_argument("--ovs-timeout", type=float, default=10.0, help="OVS command timeout (default: 10)")
    parser.add_argument("--k8s-timeout", type=float, default=10.0, help="Kubernetes API timeout (default: 10)")
    parser.add_argument("--connect-timeout", type=float, default=3.0, help="TCP connect timeout (default: 3)")


def _build_config(args: argparse.Namespace) -> RuntimeConfig:
    """Build a RuntimeConfig from parsed arguments."""
    return RuntimeConfig(
        namespace=getattr(args, "namespace", None),
        source=getattr(args, "source", None),
        destination=getattr(args, "destination", None),
        pod=getattr(args, "pod", None),
        port=getattr(args, "port", None),
        protocol=getattr(args, "protocol", "tcp"),
        json_output=getattr(args, "json_output", False),
        verbose=getattr(args, "verbose", False),
        mock=getattr(args, "mock", False),
        mock_data_path=getattr(args, "mock_data_path", None),
        kubeconfig=getattr(args, "kubeconfig", None),
        timeout=getattr(args, "timeout", 5.0),
        ovn_timeout=getattr(args, "ovn_timeout", 10.0),
        ovs_timeout=getattr(args, "ovs_timeout", 10.0),
        k8s_timeout=getattr(args, "k8s_timeout", 10.0),
        connect_timeout=getattr(args, "connect_timeout", 3.0),
    )


def cmd_diagnose(config: RuntimeConfig) -> int:
    """Execute the diagnose command."""
    engine = DiagnosticEngine(config)
    report = engine.diagnose(
        namespace=config.namespace,
        source=config.source,
        destination=config.destination,
        port=config.port,
        protocol=config.protocol,
    )
    if config.json_output:
        print(Reporter.to_json(report))
    else:
        print(Reporter.to_text(report))
    return 0


def cmd_cluster_info(config: RuntimeConfig) -> int:
    """Execute the cluster-info command."""
    engine = DiagnosticEngine(config)
    info = engine.cluster_info()
    if config.json_output:
        print(Reporter.to_json_str(info))
    else:
        print(Reporter.format_cluster_info(info))
    return 0


def cmd_pod_info(config: RuntimeConfig) -> int:
    """Execute the pod-info command."""
    engine = DiagnosticEngine(config)
    info = engine.pod_info(config.namespace, config.pod)
    if config.json_output:
        print(Reporter.to_json_str(info))
    else:
        print(Reporter.format_pod_info(info))
    return 0


def cmd_ovn_info(config: RuntimeConfig) -> int:
    """Execute the ovn-info command."""
    engine = DiagnosticEngine(config)
    info = engine.ovn_info()
    if config.json_output:
        print(Reporter.to_json_str(info))
    else:
        print(Reporter.format_ovn_info(info))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the CLI.

    Args:
        argv: Command-line arguments. If None, uses sys.argv.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    configure_logging(verbose=getattr(args, "verbose", False))

    config = _build_config(args)

    try:
        if args.command == "diagnose":
            return cmd_diagnose(config)
        elif args.command == "cluster-info":
            return cmd_cluster_info(config)
        elif args.command == "pod-info":
            return cmd_pod_info(config)
        elif args.command == "ovn-info":
            return cmd_ovn_info(config)
        else:
            parser.print_help()
            return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        if config.json_output:
            print(json.dumps({"error": str(exc)}, indent=2))
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
