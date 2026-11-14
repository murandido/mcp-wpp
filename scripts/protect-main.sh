#!/usr/bin/env bash
# Make the CI gates binding on GitHub. Run once after the first push:
#   scripts/protect-main.sh [owner/repo]
#
# - main only changes through pull requests that pass the "All gates" check
# - squash merges only, with the PR title (validated by CI) as the commit
#   subject, so main's history stays type(scope): summary
# - no force pushes or deletion of main; linear history
set -euo pipefail
repo=${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}

gh api -X PATCH "repos/$repo" \
	-F allow_squash_merge=true -F allow_merge_commit=false -F allow_rebase_merge=false \
	-f squash_merge_commit_title=PR_TITLE -f squash_merge_commit_message=PR_BODY \
	-F delete_branch_on_merge=true >/dev/null

gh api -X PUT "repos/$repo/branches/main/protection" --input - >/dev/null <<'JSON'
{
  "required_status_checks": { "strict": true, "contexts": ["All gates"] },
  "enforce_admins": true,
  "required_pull_request_reviews": { "required_approving_review_count": 0, "dismiss_stale_reviews": true },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON
echo "main is protected on $repo: PRs only, \"All gates\" required, squash merges titled by the PR."
