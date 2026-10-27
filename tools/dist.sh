#!/bin/sh
# openUF release packaging
#
# Builds openuf.tar.gz from a comment-stripped copy of the tree. OpenWrt
# devices are flash-constrained and roughly half of openuf/'s bytes are
# comments, so the repo keeps its protocol-archaeology commentary and the
# device does not.
#
# Usage:
#   sh tools/dist.sh            — build openuf.tar.gz
#   sh tools/dist.sh --verify   — build, then prove the stripped tree is
#                                 bytecode-identical and still passes the suite

set -e

BUILD=build
STAGE=$BUILD/openuf
TARBALL=openuf.tar.gz

# conf.lua and the modelmaps are the files a user is *expected* to hand-edit on
# the device (modelmap selection, inform_url, radio names, LED sysfs path).
# Their comments are operating instructions, so they ship intact -- ~1.8 KB of
# the ~84 KB result, and worth it.
keep_comments() {
	case "$1" in
		openuf/conf.lua|openuf/modelmap/*) return 0 ;;
		*) return 1 ;;
	esac
}

# ── Stage ───────────────────────────────────────────────────────────────────
rm -rf "$BUILD"
mkdir -p "$STAGE"

for src in $(find openuf -type f | sort); do
	dst="$STAGE/${src#openuf/}"
	mkdir -p "$(dirname "$dst")"

	case "$src" in
		*.lua)
			if keep_comments "$src"; then
				cp "$src" "$dst"
			else
				lua tools/strip.lua "$src" > "$dst"
			fi
			;;
		*.sh|*/init.d/*)
			# Full-line comments only, and never line 1 -- the shebang is
			# functional (init.d's is `#!/bin/sh /etc/rc.common`), and a
			# mid-line "#" may be a parameter expansion such as ${#key}.
			awk 'NR==1 || $0 !~ /^[[:space:]]*#/' "$src" > "$dst"
			;;
		*)
			cp "$src" "$dst"
			;;
	esac
done

# Preserve the executable bit the installer relies on.
chmod +x "$STAGE/etc/init.d/openuf" "$STAGE/hook/syswrapper.sh" \
	"$STAGE/hook/adopt-shell.sh"

cp install.sh LICENSE "$BUILD/"

# ── Verify ──────────────────────────────────────────────────────────────────
# README.md/USAGE.md are deliberately not shipped: ~21 KB transferred to and
# extracted on the device for no runtime purpose. They live in the repo and on
# the release page.
if [ "$1" = "--verify" ]; then
	echo "verify: bytecode equivalence"

	LUAC=$(command -v luac5.1 || command -v luac || true)
	if [ -z "$LUAC" ]; then
		echo "  SKIP (no luac available)"
	else
		# Normalise away the things that legitimately differ: the source
		# filename, heap addresses, and the line-number column (comments are
		# gone, so line numbers shift). What remains is the opcode stream --
		# identical output proves the strip changed nothing but comments.
		norm() {
			"$LUAC" -l -l -p "$1" 2>/dev/null \
				| grep -v 'instructions at' \
				| sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+\[[0-9]+\][[:space:]]+/ /' \
				| sed -E 's/0x[0-9a-f]+/ADDR/g; s/<[^>]*:[0-9]+,[0-9]+>/<F>/g'
		}
		for src in $(find openuf -name '*.lua' | sort); do
			dst="$STAGE/${src#openuf/}"
			norm "$src" > "$BUILD/.a"
			norm "$dst" > "$BUILD/.b"
			if ! diff -q "$BUILD/.a" "$BUILD/.b" >/dev/null; then
				echo "  FAIL $src -- opcodes differ after strip"
				diff "$BUILD/.a" "$BUILD/.b" | head -20
				exit 1
			fi
		done
		rm -f "$BUILD/.a" "$BUILD/.b"
		echo "  OK   all stripped files are bytecode-identical"
	fi

	echo "verify: test suite against the stripped tree"
	# The suite dofile()s "openuf/..." relative to cwd, so running it from a
	# directory whose openuf/ is the stripped one tests exactly what ships.
	rm -rf "$BUILD/verify"
	mkdir -p "$BUILD/verify"
	cp -r "$STAGE" "$BUILD/verify/openuf"
	cp -r tests "$BUILD/verify/tests"
	# The installer tests source install.sh from the project root; ship-identical.
	cp install.sh "$BUILD/verify/"
	# tools/ is not shipped, but the suite dofile()s one of them
	# (tools/cfg-coverage.lua), so the verify tree needs it present.
	cp -r tools "$BUILD/verify/tools"
	if ! ( cd "$BUILD/verify" && lua tests/run_tests.lua ); then
		echo ""
		echo "  FAIL tests do not pass against the stripped tree -- not packaging."
		echo "       Run 'lua tests/run_tests.lua' on the unstripped tree first:"
		echo "       if it fails there too, the cause is the environment (missing"
		echo "       cjson/openssl bindings), not the strip."
		exit 1
	fi
	rm -rf "$BUILD/verify"
fi

# ── Package ─────────────────────────────────────────────────────────────────
rm -f "$TARBALL"
tar czf "$TARBALL" -C "$BUILD" openuf install.sh LICENSE

before=$(find openuf -type f -exec cat {} + | wc -c | tr -d ' ')
after=$(find "$STAGE" -type f -exec cat {} + | wc -c | tr -d ' ')
echo ""
echo "$TARBALL  $(wc -c < "$TARBALL" | tr -d ' ') bytes"
echo "installed tree: $before -> $after bytes"
