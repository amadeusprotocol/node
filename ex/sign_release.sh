#!/bin/bash
# Sign a built release for the node's auto-updater.
#
# Produces ONE asset to upload to the GitHub release ALONGSIDE amadeusd:
#     amadeusd.sig  ->  "<version> <sha256>\n" followed by the armored SSHSIG
#                       over that exact line (ssh-keygen -Y sign).
#
# A node only installs an update whose bundle is signed by a pubkey pinned in
# lib/misc/autoupdate_release_verify.ex, whose sha256 matches the downloaded binary, and
# whose version is strictly newer than what it runs. No amadeusd.sig => no update.
#
# Safe to run on ANY machine: if this box doesn't hold the pinned signing key
# (e.g. someone else's build box), it prints a notice and skips — the build still
# succeeds, the release just isn't signed (and so won't be auto-installed).
set -uo pipefail

BIN="${1:-amadeusd}"
KEY="${RELEASE_KEY:-$HOME/.ssh/id_ed25519}"
NAMESPACE="amadeus-release"
PINFILE="lib/misc/autoupdate_release_verify.ex"

skip() { echo "signing key not found, skipping signed release"; exit 0; }

[ -f "$BIN" ] || { echo "no binary at $BIN"; exit 0; }
[ -f "$KEY" ] || skip

# raw ed25519 pubkey of the local key, as comma-joined decimal bytes (matches the
# Elixir literal in autoupdate_release_verify.ex). empty if the key is unreadable / not ed25519.
LOCAL_BYTES=$(ssh-keygen -y -f "$KEY" 2>/dev/null | awk '{print $2}' | python3 -c "
import sys, base64, struct
try:
    blob = base64.b64decode(sys.stdin.read().strip())
    def rd(b, o):
        n = struct.unpack('>I', b[o:o+4])[0]; return b[o+4:o+4+n], o+4+n
    t, o = rd(blob, 0); key, _ = rd(blob, o)
    assert t == b'ssh-ed25519' and len(key) == 32
    print(','.join(str(x) for x in key))
except Exception:
    pass
")
[ -n "$LOCAL_BYTES" ] || skip

# is THIS key one of the pubkeys pinned in the binary? (whitespace-insensitive)
tr -d ' \n\t' < "$PINFILE" 2>/dev/null | grep -qF "$LOCAL_BYTES" || skip

VERSION=$(grep -oP 'version:\s*"\K[^"]+' mix.exs | head -1)
SHA=$(sha256sum "$BIN" | awk '{print $1}')

# sign the manifest line, then bundle "manifest line + armored sig" into one asset
TMP=$(mktemp)
printf '%s %s\n' "$VERSION" "$SHA" > "$TMP"
rm -f "$TMP.sig"
ssh-keygen -Y sign -n "$NAMESPACE" -f "$KEY" "$TMP" >/dev/null
cat "$TMP" "$TMP.sig" > "$BIN.sig"
rm -f "$TMP" "$TMP.sig"

echo "signed release $VERSION with $KEY (sha256 $SHA)"
echo "upload to the '$VERSION' github release: $BIN  $BIN.sig"
