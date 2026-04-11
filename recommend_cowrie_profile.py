#!/usr/bin/env python3
"""Recommend a Cowrie profile from CSV log exports using Thompson sampling.

The script supports a simple workflow:
1. Open a file picker and choose a CSV log export.
2. Parse Cowrie events from the file.
3. Score a set of candidate profiles against the observed traffic.
4. Use Thompson sampling over those profile rewards.
"""

from __future__ import annotations

import argparse
import csv
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from tkinter import Tk, filedialog


PROFILE_DEFINITIONS = {
    "default": {
        "expected_usernames": {"root", "admin", "user", "ubuntu"},
        "expected_passwords": {"root", "admin", "user", "ubuntu", "123456", "password"},
        "persona": "generic",
    },
    "server": {
        "expected_usernames": {"root", "admin", "ubuntu", "oracle", "postgres", "mysql", "deploy", "sysadmin"},
        "expected_passwords": {
            "123456",
            "password",
            "Passw0rd",
            "Root@123",
            "root@2026",
            "redhat",
            "Huawei@123",
        },
        "persona": "server",
    },
    "workstation": {
        "expected_usernames": {"user", "labuser", "media", "git", "oscar", "luna", "reza", "vivek"},
        "expected_passwords": {"1234", "12345", "123456", "user", "labuser", "vivek", "luna", "oscar123"},
        "persona": "workstation",
    },
    "legacy": {
        "expected_usernames": {"admin", "root", "user", "ubnt", "ftpuser", "vncuser", "AdminGPON", "sol", "solv"},
        "expected_passwords": {"admin", "root", "123", "1234", "123456", "ubnt", "vncuser", "ALC#FGU", "NIMDA"},
        "persona": "legacy",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recommend a Cowrie profile from exported JSON logs."
    )
    parser.add_argument(
        "--current-profile",
        default="default",
        choices=sorted(PROFILE_DEFINITIONS),
        help="Current active Cowrie profile.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional random seed for reproducible Thompson sampling.",
    )
    parser.add_argument(
        "--csv-file",
        type=Path,
        default=None,
        help="Path to CSV file. If omitted, a file picker is shown.",
    )
    return parser.parse_args()


def pick_csv_file() -> Path | None:
    root = Tk()
    root.withdraw()
    root.update()
    selected = filedialog.askopenfilename(
        title="Vyber CSV log subor",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
    )
    root.destroy()
    if not selected:
        return None
    return Path(selected)


def first_nonempty(row: dict, keys: list[str], default: str = "") -> str:
    for key in keys:
        value = row.get(key, "")
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return default


def load_csv_events(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV subor nema hlavicku.")
        rows = list(reader)

    events = []
    for row in rows:
        eventid = first_nonempty(row, ["eventid", "eventid.keyword"])
        if not eventid.startswith("cowrie."):
            continue

        username = first_nonempty(row, ["username", "username.keyword"])
        password = first_nonempty(row, ["password", "password.keyword"])
        src_ip = first_nonempty(row, ["src_ip", "src_ip.keyword"])
        session = first_nonempty(row, ["session", "session.keyword"])
        country = first_nonempty(row, ["geoip.country_code2", "geoip.country_code2.keyword", "country"])
        ip_rep = first_nonempty(row, ["ip_rep", "ip_rep.keyword"])
        message = first_nonempty(row, ["message"])
        timestamp = first_nonempty(row, ["@timestamp", "timestamp"])

        events.append(
            {
                "eventid": eventid,
                "username": username,
                "password": password,
                "src_ip": src_ip,
                "session": session,
                "country": country,
                "ip_rep": ip_rep,
                "message": message,
                "timestamp": timestamp,
            }
        )
    return events


def build_stats(events: list[dict]) -> dict:
    stats = {
        "total_events": len(events),
        "login_failed": 0,
        "login_success": 0,
        "command_input": 0,
        "unique_sessions": set(),
        "unique_src_ip": set(),
        "unique_credentials": set(),
        "username_counter": Counter(),
        "password_counter": Counter(),
        "country_counter": Counter(),
        "known_attacker_events": 0,
        "commands_per_session": defaultdict(int),
    }

    for event in events:
        eventid = event["eventid"]
        username = event["username"]
        password = event["password"]
        session = event["session"]
        src_ip = event["src_ip"]
        country = event["country"]
        ip_rep = event["ip_rep"]

        if session:
            stats["unique_sessions"].add(session)
        if src_ip:
            stats["unique_src_ip"].add(src_ip)
        if username or password:
            stats["unique_credentials"].add(f"{username}:{password}")
        if username:
            stats["username_counter"][username] += 1
        if password:
            stats["password_counter"][password] += 1
        if country:
            stats["country_counter"][country] += 1
        if ip_rep == "known attacker":
            stats["known_attacker_events"] += 1

        if eventid == "cowrie.login.failed":
            stats["login_failed"] += 1
        elif eventid == "cowrie.login.success":
            stats["login_success"] += 1
        elif eventid == "cowrie.command.input":
            stats["command_input"] += 1
            if session:
                stats["commands_per_session"][session] += 1

    stats["unique_sessions_count"] = len(stats["unique_sessions"])
    stats["unique_src_ip_count"] = len(stats["unique_src_ip"])
    stats["unique_credentials_count"] = len(stats["unique_credentials"])
    stats["known_attacker_ratio"] = (
        stats["known_attacker_events"] / stats["total_events"] if stats["total_events"] else 0.0
    )
    stats["avg_commands_per_session"] = (
        statistics.mean(stats["commands_per_session"].values())
        if stats["commands_per_session"]
        else 0.0
    )
    return stats


def bounded_ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return max(0.0, min(1.0, numerator / denominator))


def normalize_count(value: float, saturation_point: float) -> float:
    if saturation_point <= 0:
        return 0.0
    return max(0.0, min(1.0, value / saturation_point))


def profile_match_score(stats: dict, profile_name: str) -> float:
    definition = PROFILE_DEFINITIONS[profile_name]
    expected_usernames = definition["expected_usernames"]
    expected_passwords = definition["expected_passwords"]

    username_hits = sum(
        count for username, count in stats["username_counter"].items() if username in expected_usernames
    )
    password_hits = sum(
        count for password, count in stats["password_counter"].items() if password in expected_passwords
    )

    total_username_obs = sum(stats["username_counter"].values())
    total_password_obs = sum(stats["password_counter"].values())

    # If CSV contains only eventid and timestamp, do not punish the model for missing fields.
    username_match = 0.25 if total_username_obs == 0 else bounded_ratio(username_hits, total_username_obs)
    password_match = 0.25 if total_password_obs == 0 else bounded_ratio(password_hits, total_password_obs)

    if definition["persona"] == "server":
        persona_bonus = 0.15 * bounded_ratio(stats["command_input"], max(1, stats["total_events"] * 0.05))
    elif definition["persona"] == "workstation":
        persona_bonus = 0.10 * bounded_ratio(stats["unique_credentials_count"], 20)
    elif definition["persona"] == "legacy":
        persona_bonus = 0.10 * bounded_ratio(stats["known_attacker_ratio"], 1.0)
    else:
        persona_bonus = 0.05

    return min(1.0, 0.45 * username_match + 0.40 * password_match + persona_bonus)


def engagement_score(stats: dict) -> float:
    success_component = normalize_count(stats["login_success"], 2)
    command_component = normalize_count(stats["command_input"], 5)
    session_component = normalize_count(stats["unique_sessions_count"], 10)
    cred_component = normalize_count(stats["unique_credentials_count"], 20)
    failure_component = normalize_count(stats["login_failed"], 30)
    return min(
        1.0,
        0.40 * success_component
        + 0.30 * command_component
        + 0.10 * session_component
        + 0.10 * cred_component
        + 0.10 * failure_component,
    )


def reward_probability(stats: dict, profile_name: str) -> float:
    match = profile_match_score(stats, profile_name)
    engagement = engagement_score(stats)

    failure_activity = min(
        1.0,
        0.5 * normalize_count(stats["login_failed"], 25)
        + 0.5 * normalize_count(stats["unique_credentials_count"], 20),
    )

    # Even without successful logins, a profile may still be useful if it attracts
    # a wide password spray aligned with its persona.
    probability = 0.55 * match + 0.30 * engagement + 0.15 * failure_activity
    return max(0.05, min(0.95, probability))


def beta_parameters(probability: float, concentration: float = 12.0) -> tuple[float, float]:
    alpha = 1.0 + probability * concentration
    beta = 1.0 + (1.0 - probability) * concentration
    return alpha, beta


def recommend_profile(stats: dict, current_profile: str) -> tuple[str, dict]:
    samples = {}
    details = {}

    for profile_name in PROFILE_DEFINITIONS:
        probability = reward_probability(stats, profile_name)
        alpha, beta = beta_parameters(probability)
        sample = random.betavariate(alpha, beta)
        samples[profile_name] = sample
        details[profile_name] = {
            "probability": probability,
            "alpha": alpha,
            "beta": beta,
            "sample": sample,
        }

    recommended = max(samples, key=samples.get)

    # Mild hysteresis: do not switch if the new sample is only trivially better.
    current_sample = details[current_profile]["sample"]
    recommended_sample = details[recommended]["sample"]
    if recommended != current_profile and recommended_sample - current_sample < 0.03:
        recommended = current_profile

    return recommended, details


def print_summary(path: Path, stats: dict, current_profile: str, recommended: str, details: dict) -> None:
    print(f"\nSubor: {path}")
    print(f"Aktualny profil: {current_profile}")
    print(f"Odporucany profil: {recommended}")
    print("\nSuhrnne metriky:")
    print(f"- Cowrie eventy: {stats['total_events']}")
    print(f"- login.failed: {stats['login_failed']}")
    print(f"- login.success: {stats['login_success']}")
    print(f"- command.input: {stats['command_input']}")
    print(f"- unikatne session: {stats['unique_sessions_count']}")
    print(f"- unikatne src_ip: {stats['unique_src_ip_count']}")
    print(f"- unikatne credentials: {stats['unique_credentials_count']}")
    print(f"- known attacker ratio: {stats['known_attacker_ratio']:.2f}")

    top_users = ", ".join(f"{name}:{count}" for name, count in stats["username_counter"].most_common(5))
    top_passwords = ", ".join(
        f"{name}:{count}" for name, count in stats["password_counter"].most_common(5)
    )
    if top_users:
        print(f"- top usernames: {top_users}")
    if top_passwords:
        print(f"- top passwords: {top_passwords}")

    print("\nThompson sampling detail:")
    for profile_name, info in sorted(details.items(), key=lambda item: item[1]["sample"], reverse=True):
        print(
            f"- {profile_name}: "
            f"reward_p={info['probability']:.3f}, "
            f"alpha={info['alpha']:.2f}, "
            f"beta={info['beta']:.2f}, "
            f"sample={info['sample']:.3f}"
        )

    if recommended == current_profile:
        print("\nZaver: profil zatial nemenit.")
    else:
        print(f"\nZaver: odporucena zmena z '{current_profile}' na '{recommended}'.")


def main() -> int:
    args = parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    path = args.csv_file or pick_csv_file()
    if path is None:
        print("Nebol vybrany ziadny subor.", file=sys.stderr)
        return 1

    try:
        events = load_csv_events(path)
        if not events:
            print("V subore sa nenasli ziadne Cowrie eventy.", file=sys.stderr)
            return 1

        stats = build_stats(events)
        recommended, details = recommend_profile(stats, args.current_profile)
        print_summary(path, stats, args.current_profile, recommended, details)
    except Exception as exc:  # pragma: no cover - CLI guard
        print(f"Chyba pri spracovani logov: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
