#!/usr/bin/env bash
set -euo pipefail

BASE="/home/filip/adaptive_honeypot"
TPOT="/home/filip/tpotce"

SERVICE="${1:-}"
PROFILE="${2:-}"

usage() {
  echo "Usage:"
  echo "  $0 cowrie <profile|random>"
  echo "  $0 dionaea <profile|random>"
  exit 1
}

pick_random_profile() {
  local dir="$1"
  find "$dir" -mindepth 1 -maxdepth 1 -type d | shuf -n 1 | xargs -n 1 basename
}

apply_cowrie() {
  local profile="$1"
  local src="$BASE/profiles/cowrie/$profile"

  local dst_cfg="$TPOT/data/cowrie/config/cowrie.cfg"
  local dst_honeyfs="$TPOT/data/cowrie/honeyfs"
  local dst_userdb="$TPOT/data/cowrie/keys/userdb.txt"

  [[ -d "$src" ]] || { echo "Cowrie profile not found: $profile"; exit 1; }
  [[ -f "$src/cowrie.cfg" ]] || { echo "Missing cowrie.cfg in profile $profile"; exit 1; }
  [[ -d "$src/honeyfs" ]] || { echo "Missing honeyfs/ in profile $profile"; exit 1; }
  [[ -f "$src/userdb.txt" ]] || { echo "Missing userdb.txt in profile $profile"; exit 1; }

  echo "[+] Applying Cowrie profile: $profile"

  cp "$src/cowrie.cfg" "$dst_cfg"
  cp "$src/userdb.txt" "$dst_userdb"

  rm -rf "$dst_honeyfs"
  mkdir -p "$dst_honeyfs"
  cp -a "$src/honeyfs/." "$dst_honeyfs/"

  (cd "$TPOT" && docker compose restart cowrie)

  echo "[+] Cowrie profile applied: $profile"
}

apply_dionaea() {
  local profile="$1"
  local src="$BASE/profiles/dionaea/$profile"

  local dst_cfg="$TPOT/data/dionaea/config/dionaea.conf"

  [[ -d "$src" ]] || { echo "Dionaea profile not found: $profile"; exit 1; }
  [[ -f "$src/dionaea.conf" ]] || { echo "Missing dionaea.conf in profile $profile"; exit 1; }

  echo "[+] Applying Dionaea profile: $profile"

  cp "$src/dionaea.conf" "$dst_cfg"

  (cd "$TPOT" && docker compose restart dionaea)

  echo "[+] Dionaea profile applied: $profile"
}

main() {
  [[ -n "$SERVICE" ]] || usage
  [[ -n "$PROFILE" ]] || usage

  case "$SERVICE" in
    cowrie)
      if [[ "$PROFILE" == "random" ]]; then
        PROFILE="$(pick_random_profile "$BASE/profiles/cowrie")"
      fi
      apply_cowrie "$PROFILE"
      ;;
    dionaea)
      if [[ "$PROFILE" == "random" ]]; then
        PROFILE="$(pick_random_profile "$BASE/profiles/dionaea")"
      fi
      apply_dionaea "$PROFILE"
      ;;
    *)
      usage
      ;;
  esac
}

main