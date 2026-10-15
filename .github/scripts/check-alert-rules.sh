#!/usr/bin/env bash
# Checks the alert rules in monitoring/: each rules file has a test file, no group holds more than
# 20 rules (Mysten's Mimir ruler rejects bigger groups), every hashi_* or guardian_proxy_* name a
# rule mentions is still a string literal in the code, and promtool's check and tests pass.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if ! command -v promtool >/dev/null; then
	echo "::error::promtool is not on PATH; .github/workflows/ci.yml pins the version CI uses"
	exit 1
fi

shopt -s nullglob
rules=(monitoring/*.rules.yml)
tests=(monitoring/*.test.yml)
if [ ${#rules[@]} -eq 0 ]; then
	echo "::error::no monitoring/*.rules.yml found"
	exit 1
fi

status=0
for f in "${rules[@]}"; do
	if [ ! -f "${f%.rules.yml}.test.yml" ]; then
		echo "::error file=$f::missing ${f%.rules.yml}.test.yml"
		status=1
	fi
done
for f in ${tests[@]+"${tests[@]}"}; do
	if [ ! -f "${f%.test.yml}.rules.yml" ]; then
		echo "::error file=$f::missing ${f%.test.yml}.rules.yml"
		status=1
	fi
done

for f in "${rules[@]}"; do
	awk -v f="$f" '
		function check() { if (n > 20) { print "::error file=" f "::group " g " has " n " rules, more than 20"; bad = 1 } }
		/^[[:space:]]*- name:/ { check(); g = $3; n = 0 }
		/^[[:space:]]*- alert:/ { n++ }
		END { check(); exit bad }
	' "$f" || status=1
done

# Each rules file reads the metrics of one crate. A histogram is mentioned by its _bucket, _sum
# or _count series, and a trailing * marks a prefix.
for f in "${rules[@]}"; do
	case $(basename "$f" .rules.yml) in
	hashi-node) src=crates/hashi/src ;;
	hashi-monitor) src=crates/hashi-monitor/src ;;
	guardian-proxy) src=crates/hashi-guardian-proxy/src ;;
	hashi-fleet) src=crates/hashi/src ;;
	*)
		echo "::error file=$f::map $f to the crate whose metrics it reads in $0"
		status=1
		continue
		;;
	esac
	while read -r name; do
		case $name in
		hashi_proxy_allowed_members)
			# sui-proxy's gauge, which the fleet rules point to.
			continue
			;;
		*'*')
			grep -rqF -- "\"${name%'*'}" "$src" && continue
			;;
		*)
			grep -rqF -- "\"$name\"" "$src" && continue
			base=$(sed -E 's/_(bucket|sum|count)$//' <<<"$name")
			[ "$base" != "$name" ] && grep -rqF -- "\"$base\"" "$src" && continue
			;;
		esac
		echo "::error file=$f::$name is not a metric $src exports"
		status=1
	done < <(grep -ohE '(^|[^A-Za-z0-9_])(hashi|guardian_proxy)_[a-z0-9_]+\*?' "$f" | sed -E 's/^[^a-z]//' | sort -u)
done

if [ $status -ne 0 ]; then
	exit $status
fi

promtool check rules "${rules[@]}"
promtool test rules ${tests[@]+"${tests[@]}"}
