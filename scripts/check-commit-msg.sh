#!/usr/bin/env bash
# Validate commit subjects: type(scope): summary, or type(scope)!: summary.
#
#   scripts/check-commit-msg.sh <file>        check a commit message file (commit-msg hook)
#   scripts/check-commit-msg.sh --range REV…   check every commit `git log REV…` lists (CI, pre-push)
#   scripts/check-commit-msg.sh --subject "…" check one subject (PR titles)
set -euo pipefail

TYPES='feat|fix|chore|docs|refactor|perf|test|build|ci|style|revert'
PATTERN="^(${TYPES})\([a-z0-9][a-z0-9._/-]*\)!?: [^ ].{0,98}[^. ]$"

check() {
	local subject=$1 where=$2
	# Git's own merge and revert subjects are allowed.
	if [[ $subject =~ ^(Merge|Revert\ \") ]]; then
		return 0
	fi
	if [[ ! $subject =~ $PATTERN ]]; then
		cat >&2 <<MSG
✗ ${where}: "${subject}"
  Expected: <type>(<scope>)[!]: <summary>   (max 100 chars, no trailing period)
  Types:    ${TYPES//|/, }
  Example:  feat(access): let the user approve chat requests from the CLI
MSG
		return 1
	fi
}

case "${1:-}" in
--range)
	status=0
	while IFS=$'\t' read -r sha subject; do
		check "$subject" "commit ${sha:0:7}" || status=1
	done < <(git log --no-merges --format='%H%x09%s' "${@:2}")
	exit $status
	;;
--subject)
	check "$2" "title"
	;;
"")
	echo "usage: $0 <message-file> | --range REV... | --subject TEXT" >&2
	exit 2
	;;
*)
	subject=$(grep -v '^#' "$1" | head -n1)
	check "$subject" "commit message"
	;;
esac
