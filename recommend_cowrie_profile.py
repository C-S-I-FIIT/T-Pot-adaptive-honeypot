"""Recommend honeypot profiles from CSV log exports using Thompson sampling."""

from __future__ import annotations

import argparse
import csv
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from tkinter import Tk, filedialog


COWRIE_PROFILES = {
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

FTP_PROFILES = {
    "windows7": {
        "expected_users": {"anonymous", "ftp", "administrator", "admin", "user"},
        "expected_commands": {"USER", "PASS", "SYST", "PWD", "TYPE"},
        "persona": "windows",
    },
    "samba_linux": {
        "expected_users": {"anonymous", "ftp", "root", "ubuntu", "admin"},
        "expected_commands": {"USER", "PASS", "PWD", "LIST", "PASV", "CWD"},
        "persona": "linux",
    },
    "legacy_xp": {
        "expected_users": {"anonymous", "administrator", "admin", "test", "guest"},
        "expected_commands": {"USER", "PASS", "SYST", "PORT", "TYPE"},
        "persona": "legacy",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recommend Cowrie or FTP/Dionaea profiles from exported CSV logs."
    )
    parser.add_argument(
        "--type",
        choices=["cowrie", "ftp"],
        required=True,
        help="Typ logov, ktore sa maju spracovat.",
    )
    parser.add_argument(
        "--current-profile",
        default=None,
        help="Current active profile. If omitted, a built-in fallback for the selected mode is used.",
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


def load_csv_rows(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV subor nema hlavicku.")
        return list(reader)


def load_cowrie_events(rows: list[dict]) -> list[dict]:
    events = []
    for row in rows:
        eventid = first_nonempty(row, ["eventid", "eventid.keyword"])
        if not eventid.startswith("cowrie."):
            continue
        events.append(
            {
                "eventid": eventid,
                "username": first_nonempty(row, ["username", "username.keyword"]),
                "password": first_nonempty(row, ["password", "password.keyword"]),
                "src_ip": first_nonempty(row, ["src_ip", "src_ip.keyword"]),
                "session": first_nonempty(row, ["session", "session.keyword"]),
                "country": first_nonempty(row, ["geoip.country_code2", "geoip.country_code2.keyword", "country"]),
                "ip_rep": first_nonempty(row, ["ip_rep", "ip_rep.keyword"]),
                "message": first_nonempty(row, ["message"]),
                "timestamp": first_nonempty(row, ["@timestamp", "timestamp"]),
            }
        )
    return events


def load_ftp_events(rows: list[dict]) -> list[dict]:
    events = []
    for row in rows:
        command = first_nonempty(row, ["ftp.command", "ftp.command_data"])
        if not command:
            continue
        raw = command.strip()
        cmd_upper = raw.upper()
        argument = ""
        if " " in raw:
            cmd_upper, argument = raw.split(" ", 1)
            cmd_upper = cmd_upper.strip().upper()
            argument = argument.strip()
        else:
            # Kibana CSV may export only the data part, e.g. "anonymous" or "PASS".
            if raw.upper() in {"USER", "PASS", "LIST", "PWD", "SYST", "TYPE", "CWD", "PASV", "PORT"}:
                cmd_upper = raw.upper()
                argument = ""
            else:
                cmd_upper = "USER_OR_DATA"
                argument = raw
        events.append(
            {
                "timestamp": first_nonempty(row, ["@timestamp", "timestamp"]),
                "src_ip": first_nonempty(row, ["src_ip", "src_ip.keyword"]),
                "ftp_command": cmd_upper,
                "ftp_argument": argument,
                "raw_command": command,
            }
        )
    return events


def bounded_ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return max(0.0, min(1.0, numerator / denominator))


def normalize_count(value: float, saturation_point: float) -> float:
    if saturation_point <= 0:
        return 0.0
    return max(0.0, min(1.0, value / saturation_point))


def beta_parameters(probability: float, concentration: float = 12.0) -> tuple[float, float]:
    alpha = 1.0 + probability * concentration
    beta = 1.0 + (1.0 - probability) * concentration
    return alpha, beta


def build_cowrie_stats(events: list[dict]) -> dict:
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
        statistics.mean(stats["commands_per_session"].values()) if stats["commands_per_session"] else 0.0
    )
    return stats


def cowrie_profile_match_score(stats: dict, profile_name: str) -> float:
    definition = COWRIE_PROFILES[profile_name]
    username_hits = sum(
        count for username, count in stats["username_counter"].items() if username in definition["expected_usernames"]
    )
    password_hits = sum(
        count for password, count in stats["password_counter"].items() if password in definition["expected_passwords"]
    )

    total_username_obs = sum(stats["username_counter"].values())
    total_password_obs = sum(stats["password_counter"].values())

    username_match = 0.25 if total_username_obs == 0 else bounded_ratio(username_hits, total_username_obs)
    password_match = 0.25 if total_password_obs == 0 else bounded_ratio(password_hits, total_password_obs)

    if definition["persona"] == "server":
        persona_bonus = 0.15 * bounded_ratio(stats["command_input"], max(1, stats["total_events"] * 0.05))
    elif definition["persona"] == "workstation":
        persona_bonus = 0.10 * bounded_ratio(stats["unique_credentials_count"], 20)
    elif definition["persona"] == "legacy":
        persona_bonus = 0.10 * bounded_ratio(stats["known_attacker_ratio"], 1.0)
    else:
        persona_bonus = 0.0

    return min(1.0, 0.45 * username_match + 0.40 * password_match + persona_bonus)


def cowrie_engagement_score(stats: dict) -> float:
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


def cowrie_reward_probability(stats: dict, profile_name: str) -> float:
    match = cowrie_profile_match_score(stats, profile_name)
    engagement = cowrie_engagement_score(stats)
    failure_activity = min(
        1.0,
        0.5 * normalize_count(stats["login_failed"], 25)
        + 0.5 * normalize_count(stats["unique_credentials_count"], 20),
    )
    probability = 0.55 * match + 0.30 * engagement + 0.15 * failure_activity
    return max(0.05, min(0.95, probability))


def build_ftp_stats(events: list[dict]) -> dict:
    stats = {
        "total_events": len(events),
        "unique_src_ip": set(),
        "command_counter": Counter(),
        "user_counter": Counter(),
        "pass_counter": Counter(),
        "anonymous_attempts": 0,
        "login_pairs": set(),
        "sessions_by_ip": defaultdict(int),
    }

    pending_user_by_ip: dict[str, str] = {}

    for event in events:
        src_ip = event["src_ip"]
        command = event["ftp_command"]
        argument = event["ftp_argument"]

        if src_ip:
            stats["unique_src_ip"].add(src_ip)
            stats["sessions_by_ip"][src_ip] += 1

        if command:
            stats["command_counter"][command] += 1

        if command in {"USER", "USER_OR_DATA"}:
            user_value = argument or "anonymous"
            stats["user_counter"][user_value] += 1
            pending_user_by_ip[src_ip] = user_value
            if user_value.lower().startswith("anonymous"):
                stats["anonymous_attempts"] += 1

        if command == "PASS":
            pass_value = argument or "<empty>"
            stats["pass_counter"][pass_value] += 1
            user_value = pending_user_by_ip.get(src_ip, "<unknown>")
            stats["login_pairs"].add(f"{user_value}:{pass_value}")

    stats["unique_src_ip_count"] = len(stats["unique_src_ip"])
    stats["login_pair_count"] = len(stats["login_pairs"])
    stats["anonymous_ratio"] = bounded_ratio(stats["anonymous_attempts"], max(1, stats["command_counter"]["USER"]))
    return stats


def ftp_profile_match_score(stats: dict, profile_name: str) -> float:
    definition = FTP_PROFILES[profile_name]
    user_hits = sum(count for user, count in stats["user_counter"].items() if user in definition["expected_users"])
    cmd_hits = sum(
        count for command, count in stats["command_counter"].items() if command in definition["expected_commands"]
    )

    total_user_obs = sum(stats["user_counter"].values())
    total_cmd_obs = sum(stats["command_counter"].values())

    user_match = 0.30 if total_user_obs == 0 else bounded_ratio(user_hits, total_user_obs)
    cmd_match = 0.30 if total_cmd_obs == 0 else bounded_ratio(cmd_hits, total_cmd_obs)

    if definition["persona"] == "windows":
        persona_bonus = 0.15 * bounded_ratio(stats["command_counter"]["SYST"], max(1, total_cmd_obs))
    elif definition["persona"] == "linux":
        persona_bonus = 0.15 * bounded_ratio(
            stats["command_counter"]["LIST"] + stats["command_counter"]["CWD"] + stats["command_counter"]["PASV"],
            max(1, total_cmd_obs),
        )
    else:
        persona_bonus = 0.10 * stats["anonymous_ratio"]

    return min(1.0, 0.45 * user_match + 0.40 * cmd_match + persona_bonus)


def ftp_engagement_score(stats: dict) -> float:
    command_component = normalize_count(stats["total_events"], 30)
    ip_component = normalize_count(stats["unique_src_ip_count"], 10)
    login_component = normalize_count(stats["login_pair_count"], 10)
    return min(1.0, 0.45 * command_component + 0.25 * ip_component + 0.30 * login_component)


def ftp_reward_probability(stats: dict, profile_name: str) -> float:
    match = ftp_profile_match_score(stats, profile_name)
    engagement = ftp_engagement_score(stats)
    anonymous_component = stats["anonymous_ratio"]
    probability = 0.55 * match + 0.30 * engagement + 0.15 * anonymous_component
    return max(0.05, min(0.95, probability))


def recommend_from_probabilities(probabilities: dict[str, float], current_profile: str) -> tuple[str, dict]:
    details = {}
    for profile_name, probability in probabilities.items():
        alpha, beta = beta_parameters(probability)
        details[profile_name] = {
            "probability": probability,
            "alpha": alpha,
            "beta": beta,
            "sample": random.betavariate(alpha, beta),
        }

    recommended = max(details, key=lambda name: details[name]["sample"])
    if current_profile in details:
        current_sample = details[current_profile]["sample"]
        recommended_sample = details[recommended]["sample"]
        if recommended != current_profile and recommended_sample - current_sample < 0.03:
            recommended = current_profile
    return recommended, details


def print_sampling_detail(details: dict) -> None:
    print("\nThompson sampling detail:")
    for profile_name, info in sorted(details.items(), key=lambda item: item[1]["sample"], reverse=True):
        print(
            f"- {profile_name}: reward_p={info['probability']:.3f}, "
            f"alpha={info['alpha']:.2f}, beta={info['beta']:.2f}, sample={info['sample']:.3f}"
        )


def print_cowrie_summary(path: Path, stats: dict, current_profile: str, recommended: str, details: dict) -> None:
    print(f"\nSubor: {path}")
    print("Typ logov: Cowrie")
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
    top_passwords = ", ".join(f"{name}:{count}" for name, count in stats["password_counter"].most_common(5))
    if top_users:
        print(f"- top usernames: {top_users}")
    if top_passwords:
        print(f"- top passwords: {top_passwords}")

    print_sampling_detail(details)
    if recommended == current_profile:
        print("\nZaver: profil zatial nemenit.")
    else:
        print(f"\nZaver: odporucena zmena z '{current_profile}' na '{recommended}'.")


def print_ftp_summary(path: Path, stats: dict, current_profile: str, recommended: str, details: dict) -> None:
    print(f"\nSubor: {path}")
    print("Typ logov: FTP")
    print(f"Aktualny profil: {current_profile}")
    print(f"Odporucany profil: {recommended}")
    print("\nSuhrnne metriky:")
    print(f"- FTP eventy: {stats['total_events']}")
    print(f"- unikatne src_ip: {stats['unique_src_ip_count']}")
    print(f"- login pair count: {stats['login_pair_count']}")
    print(f"- anonymous ratio: {stats['anonymous_ratio']:.2f}")

    top_cmds = ", ".join(f"{name}:{count}" for name, count in stats["command_counter"].most_common(5))
    top_users = ", ".join(f"{name}:{count}" for name, count in stats["user_counter"].most_common(5))
    if top_cmds:
        print(f"- top FTP commands: {top_cmds}")
    if top_users:
        print(f"- top FTP users: {top_users}")

    print_sampling_detail(details)
    if recommended == current_profile:
        print("\nZaver: FTP profil zatial nemenit.")
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
        rows = load_csv_rows(path)
        mode = args.type

        if mode == "cowrie":
            current_profile = args.current_profile or "server"
            if current_profile not in COWRIE_PROFILES:
                raise ValueError(f"Neznamy Cowrie profil: {current_profile}")
            events = load_cowrie_events(rows)
            if not events:
                raise ValueError("V CSV sa nenasli ziadne Cowrie eventy.")
            stats = build_cowrie_stats(events)
            probabilities = {
                profile_name: cowrie_reward_probability(stats, profile_name)
                for profile_name in COWRIE_PROFILES
            }
            recommended, details = recommend_from_probabilities(probabilities, current_profile)
            print_cowrie_summary(path, stats, current_profile, recommended, details)

        elif mode == "ftp":
            current_profile = args.current_profile or "windows7"
            if current_profile not in FTP_PROFILES:
                raise ValueError(f"Neznamy FTP profil: {current_profile}")
            events = load_ftp_events(rows)
            if not events:
                raise ValueError("V CSV sa nenasli ziadne FTP eventy.")
            stats = build_ftp_stats(events)
            probabilities = {
                profile_name: ftp_reward_probability(stats, profile_name)
                for profile_name in FTP_PROFILES
            }
            recommended, details = recommend_from_probabilities(probabilities, current_profile)
            print_ftp_summary(path, stats, current_profile, recommended, details)

        else:
            raise ValueError(f"Nepodporovany mod: {mode}")

    except Exception as exc:  # pragma: no cover - CLI guard
        print(f"Chyba pri spracovani logov: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
