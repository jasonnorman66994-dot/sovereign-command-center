import argparse
import json
import subprocess
import sys
from pathlib import Path


DEFAULT_MANIFEST = Path("campaign_launcher_manifest.json")


def load_manifest(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or "profiles" not in data:
        raise ValueError("Invalid manifest format: missing 'profiles'")
    return data


def profile_index(manifest: dict) -> dict:
    profiles = manifest.get("profiles", [])
    return {p.get("id", ""): p for p in profiles if p.get("id")}


def render_profile(profile: dict) -> str:
    launch = profile.get("launch", {})
    args = launch.get("arguments", [])
    arg_text = " ".join(str(a) for a in args)
    seq = profile.get("sequence", [])
    return (
        f"ID: {profile.get('id')}\n"
        f"Mode: {profile.get('mode')}\n"
        f"Name: {profile.get('name')}\n"
        f"Safe: {profile.get('safe')}\n"
        f"Synthetic: {profile.get('synthetic')}\n"
        f"Sequence length: {len(seq)}\n"
        f"Launch intent: {launch.get('runner', 'python')} -m {launch.get('entrypoint', 'shadow_toolkit.cli')} {arg_text}"
    )


def build_command(profile: dict) -> list[str]:
    launch = profile.get("launch", {})
    runner = str(launch.get("runner", "python"))
    entrypoint = str(launch.get("entrypoint", "shadow_toolkit.cli"))
    arguments = [str(arg) for arg in launch.get("arguments", [])]
    return [runner, "-m", entrypoint, *arguments]


def run_profile(profile: dict, execute: bool) -> int:
    command = build_command(profile)
    print("Selected profile")
    print(render_profile(profile))
    print("\nCommand")
    print(" ".join(command))

    if not execute:
        print("\nDry-run complete. Use --execute to run this command.")
        return 0

    print("\nExecuting profile command...")
    result = subprocess.run(command, check=False)
    print(f"Exit code: {result.returncode}")
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Launch campaign profiles from campaign_launcher_manifest.json"
    )
    parser.add_argument(
        "profile_id",
        nargs="?",
        help="Profile ID to run (for example: chain-01, full-spectrum-01, single-scenario_3_unauthorized_access)",
    )
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST),
        help="Path to launcher manifest JSON",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available profile IDs",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Show profile details without running",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually execute the selected profile command (default is dry-run)",
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    try:
        manifest = load_manifest(manifest_path)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 2

    profiles = profile_index(manifest)
    if args.list:
        if not profiles:
            print("No profiles found in manifest.")
            return 1
        print("Available profiles")
        for profile_id in sorted(profiles):
            print(profile_id)
        return 0

    if not args.profile_id:
        print("No profile selected. Use --list to inspect available profile IDs.", file=sys.stderr)
        return 2

    profile = profiles.get(args.profile_id)
    if not profile:
        print(f"Unknown profile ID: {args.profile_id}", file=sys.stderr)
        return 2

    if args.show and not args.execute:
        print(render_profile(profile))
        return 0

    return run_profile(profile, execute=args.execute)


if __name__ == "__main__":
    raise SystemExit(main())