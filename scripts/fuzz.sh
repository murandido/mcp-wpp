#!/usr/bin/env bash
# Run every Go fuzz target in the module for FUZZTIME each (default 20s).
# Go can fuzz only one target per invocation, so this loops over them.
# A failing input is saved under the package's testdata/fuzz/<Target>/ and
# becomes a regression test that plain `go test` runs from then on.
set -euo pipefail

FUZZTIME="${FUZZTIME:-20s}"
GO="${GO:-go}"
TAGS="${TAGS:-}"

cd "$(dirname "$0")/.."

tag_args=()
if [[ -n "$TAGS" ]]; then
	tag_args=(-tags "$TAGS")
fi

mapfile -t targets < <(grep -rl --include='*_test.go' -E '^func Fuzz[A-Za-z0-9_]+\(f \*testing\.F\)' . |
	while read -r file; do
		pkg="./$(dirname "${file#./}")"
		grep -oE '^func Fuzz[A-Za-z0-9_]+' "$file" | sed "s|^func |$pkg |"
	done | sort)

if ((${#targets[@]} == 0)); then
	echo "no fuzz targets found" >&2
	exit 1
fi

failed=0
for t in "${targets[@]}"; do
	pkg="${t% *}"
	name="${t#* }"
	echo "== $pkg $name ($FUZZTIME)"
	if ! "$GO" test "${tag_args[@]}" -run '^$' -fuzz "^${name}\$" -fuzztime "$FUZZTIME" "$pkg"; then
		failed=1
	fi
done
exit "$failed"
