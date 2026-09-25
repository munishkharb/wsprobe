#!/usr/bin/env bash
# Reject a commit message that reveals AI assistance or narrates cleaning up
# AI-style writing, or that contains an em-dash. Commit messages read as an
# engineer's: they describe the change, not how it was written.
set -euo pipefail

msg_file="${1:?usage: check-commit-msg.sh <path-to-message>}"
pattern='claude|anthropic|co-authored|generated with|ai-generated|aphorism|filler|manifesto|em-dash|em dash|clean-room|de-ai|ai-tell|ai tell|slop|cringe|bullshit'

if grep -Eiq "$pattern" "$msg_file"; then
  echo "commit-msg rejected: it mentions AI assistance or AI-writing cleanup." >&2
  echo "Describe the change in plain engineering terms." >&2
  exit 1
fi

if grep -q '\xe2\x80\x94' "$msg_file"; then
  echo "commit-msg rejected: it contains an em-dash. Use plain punctuation." >&2
  exit 1
fi
