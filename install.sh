#!/bin/sh
# openUF install/uninstall script
#
# Installs the Lua emulator onto a writable OpenWrt device.
# Run from the project root after transferring files to the device.
#
# Usage:
#   ./install.sh install    — copy files, enable service
#   ./install.sh uninstall  — remove files, disable service

INSTALL_DIR=/opt/openuf
STATE_DIR=/etc/openuf
BIN_LINK=/usr/bin/syswrapper.sh
INIT_SCRIPT=/etc/init.d/openuf

case "$1" in

	# ────────────────────────────────────────────────────────────────────────
	install)
		echo "Installing openUF to $INSTALL_DIR ..."

		# Free space on the filesystem holding $INSTALL_DIR, in KB. Used to
		# decide whether an OPTIONAL package can be afforded -- see below.
		overlay_free_kb() {
			df -k "$1" 2>/dev/null | awk 'NR==2 {print $4}'
		}

		# Feature packages are only installed when there is room to spare
		# AFTERWARDS. On a small-flash board they are collectively bigger than
		# openUF itself (nftables alone drags in ~210 KB of kernel modules), and
		# filling the overlay to 100% is far worse than losing one feature: it
		# breaks state.json writes, apk's own database, and any later upgrade.
		# Threshold is deliberately generous -- jffs2 needs slack to garbage
		# collect at all.
		OPTIONAL_MIN_FREE_KB=400
		try_optional() {
			pkg=$1; feature=$2
			if apk info -e "$pkg" >/dev/null 2>&1; then return 0; fi
			free=$(overlay_free_kb "$INSTALL_DIR")
			if [ -n "$free" ] && [ "$free" -lt "$OPTIONAL_MIN_FREE_KB" ]; then
				echo "SKIP $pkg (${free}KB free, need ${OPTIONAL_MIN_FREE_KB}KB): $feature"
				echo "     Bake it into your firmware image instead, or free space."
				return 0
			fi
			echo "Installing $pkg ($feature) ..."
			apk add "$pkg" >/dev/null 2>&1 \
				|| echo "WARNING: failed to install $pkg -- $feature will not function."
		}

		# ── openUF's own files go in FIRST ───────────────────────────────
		# Deliberately before any package install. The feature packages below
		# are collectively larger than openUF, and on a small-flash board
		# installing them first fills the overlay and leaves the product
		# itself unable to be copied at all -- observed on a 512 KB overlay,
		# where nftables' kernel modules alone (~210 KB) starved out the 126 KB
		# of Lua and the install "succeeded" with no /opt/openuf on disk.
		# Product first means a space shortage costs a feature, never openUF.

		# An existing conf.lua is the DEVICE'S, and survives. It carries the
		# modelmap selection, l2_announce and bootstrap_adopt_user -- all
		# hand-set per board and none of them re-derivable. Overwriting it
		# resets the board to generic-dualband-ap, which on an adopted AP means
		# a different lan_cpueth, a different identity MAC, and a device the
		# controller stops recognising. That hazard is why re-running the
		# installer to pick up a new dependency was previously unsafe -- and
		# why a live AP ended up without `tc` at all, because nobody dared.
		# The shipped default lands beside it as conf.lua.dist for reference.
		mkdir -p "$INSTALL_DIR"
		KEEP_CONF=
		if [ -f "$INSTALL_DIR/conf.lua" ]; then
			KEEP_CONF=$(mktemp) && cp "$INSTALL_DIR/conf.lua" "$KEEP_CONF"
		fi
		cp -r openuf/* "$INSTALL_DIR/" || {
			echo "ERROR: failed to copy openUF into $INSTALL_DIR"
			echo "  Free space: $(overlay_free_kb "$INSTALL_DIR")KB. openUF needs ~130KB"
			echo "  (comment-stripped) plus room for state and logs."
			exit 1
		}
		rm -rf "$INSTALL_DIR/etc"
		if [ -n "$KEEP_CONF" ]; then
			mv "$INSTALL_DIR/conf.lua" "$INSTALL_DIR/conf.lua.dist"
			cp "$KEEP_CONF" "$INSTALL_DIR/conf.lua" && rm -f "$KEEP_CONF"
			echo "Kept the existing conf.lua (shipped default -> conf.lua.dist)."
		fi

		# Release tarballs arrive already comment-stripped (tools/dist.sh).
		# When installing from a git clone, strip on the way in using the same
		# tool so the device gets the same lean tree -- roughly half the bytes,
		# and flash is scarce. conf.lua and the modelmaps keep their comments:
		# they are the files meant to be hand-edited on the device.
		if [ -f tools/strip.lua ] && command -v lua >/dev/null 2>&1; then
			echo "Stripping comments from installed Lua ..."
			for f in $(find "$INSTALL_DIR" -name '*.lua' \
				! -name conf.lua ! -path "$INSTALL_DIR/modelmap/*"); do
				lua tools/strip.lua "$f" > "$f.stripped" \
					&& mv "$f.stripped" "$f"
			done
		fi

		# Create state directory
		mkdir -p "$STATE_DIR"

		# Keep the device's identity across a firmware upgrade.
		# sysupgrade preserves /etc/config and a short built-in list; it knows
		# nothing about $STATE_DIR or conf.lua, so a stock `sysupgrade` drops
		# state.json -- mac, authkey, cfgversion, swvlan_backup -- and the
		# board's modelmap selection along with it. The device comes back up
		# unadopted, as a generic dualband AP, and the controller no longer
		# recognises it. Verified on a live Archer C5: `sysupgrade -b` produced
		# 29 entries and neither file was among them.
		# The Lua itself is deliberately NOT preserved -- it is reinstalled
		# from this script, and carrying an old tree onto a new OpenWrt is how
		# you get a silent version mismatch.
		SYSUPGRADE_CONF=/etc/sysupgrade.conf
		for keep in "$STATE_DIR/" "$INSTALL_DIR/conf.lua"; do
			if ! grep -qxF "$keep" "$SYSUPGRADE_CONF" 2>/dev/null; then
				# A hand-edited file need not end in a newline, and
				# appending straight onto one that does not splices our
				# path onto the user's last line: their entry is
				# destroyed and ours is never registered.  `tail -c1` is
				# empty exactly when the file already ends in a newline
				# (command substitution strips it), so this terminates
				# the last line only when it needs it.
				if [ -s "$SYSUPGRADE_CONF" ] \
					&& [ -n "$(tail -c1 "$SYSUPGRADE_CONF" 2>/dev/null)" ]; then
					echo >> "$SYSUPGRADE_CONF"
				fi
				echo "$keep" >> "$SYSUPGRADE_CONF"
				echo "Registered $keep with sysupgrade (survives a firmware upgrade)."
			fi
		done

		# Symlink syswrapper.sh into PATH
		ln -sf "$INSTALL_DIR/hook/syswrapper.sh" "$BIN_LINK"
		chmod +x "$BIN_LINK"

		# Install init.d service
		cp openuf/etc/init.d/openuf "$INIT_SCRIPT"
		chmod +x "$INIT_SCRIPT"

		# ── Dependencies, now that openUF itself is safely installed ──────
		# REQUIRED: openUF cannot function without these. They may already be
		# baked into the firmware image (the only way to fit them on a small
		# board), so a present package is silently fine.
		#
		# lua-openssl provides AES-128-CBC/GCM (luacrypto was dropped from the
		# feeds) and is effectively mandatory: the controller will not finish
		# provisioning a device that has never sent a genuine GCM inform. There
		# is no Lua zlib binding in 25.12, so inform-response decompression is
		# handled in-tree by openuf/inflate.lua and needs no package.
		MISSING=""
		for pkg in lua lua-cjson luasocket lua-openssl luabitop iw; do
			if ! apk info -e "$pkg" >/dev/null 2>&1; then
				MISSING="$MISSING $pkg"
			fi
		done
		if [ -n "$MISSING" ]; then
			echo "Installing required apk packages:$MISSING"
			apk add $MISSING || {
				echo "WARNING: failed to install:$MISSING"
				echo "  Install them by hand with: apk update && apk add$MISSING"
				echo "  Without lua-openssl in particular, adoption cannot complete"
				echo "  (the controller requires a genuine AES-128-GCM inform)."
			}
		fi

		# OPTIONAL: each one silently disables exactly one feature when absent
		# -- provisioning still reports success while the feature does nothing
		# -- so they are installed when affordable rather than merely mentioned.
		# Only where the board declares gpio LEDs its running kernel cannot drive:
	# a Xiaomi AX3000T's case LED is a gpio pair the stock filogic image has no
	# driver for, so /sys/class/leds holds only the mt76 radio LEDs -- which on
	# that board are wired to nothing. Locate then "succeeds" against an LED
	# that does not physically exist. 9 KB, and pointless on a board whose LEDs
	# already registered, hence the check rather than an unconditional install.
	if [ -d /sys/bus/platform/devices/leds ] \
		&& ! ls /sys/class/leds 2>/dev/null | grep -qv '^mt76-'; then
		try_optional kmod-leds-gpio "status LED (Locate, Manage > LED)"
	fi
	try_optional lldpd         "LLDP topology / neighbour discovery"
		try_optional hostapd-utils "Minimum RSSI, client kick, block-deauth"
		try_optional usteer        "Band Steering"
		try_optional ip-bridge     "wired clients behind the AP (bridge fdb)"
		try_optional nftables      "client Block/Unblock + Multicast/Broadcast Blocker"
		# ...and the Blocker half additionally needs the bridge family's `meta`
		# expression, which lives in nft_meta_bridge and is NOT pulled in by
		# nftables. Missing on a stock filogic AND ath79 image alike. Without
		# it the table, chain and allow-list set all build fine and only the
		# drop rule is rejected, so the control reports success everywhere and
		# blocks nothing. firewall.lua's block-sta uses `ether saddr` only,
		# needs no module, and is unaffected -- which is what hid this.
		try_optional kmod-nft-bridge "Multicast/Broadcast Blocker (bridge meta)"
		# shaper.lua shells out to `tc` for the WiFi Speed Limit, and nothing
		# installed it -- busybox has no tc. tc-tiny is enough (htb + fq_codel).
		try_optional tc-tiny       "WiFi Speed Limit (tc)"
		# ...and the DOWNLINK half needs sch_htb while the UPLINK half needs the
		# act_police action, which is a separate module and is not in every
		# image. A filogic board has sch_htb, sch_ingress, act_gact, act_mirred
		# and act_skbedit but NO act_police: `tc filter ... police` fails with
		# "Failed to load TC action module", so the download cap applies and the
		# upload cap silently does not. Half a feature reporting success.
		try_optional kmod-sched-act-police "WiFi Speed Limit, upload half (tc police)"
		# inform.lua detects an out-of-process state.json write (syswrapper's
		# SSH set-adopt, a manual reset-inform) with `stat -c %Y`. Some builds
		# ship no stat applet at all -- confirmed on a real WDR3500 -- and
		# without it those changes go unnoticed until openUF is restarted.
		# Cheaper than this package: enable busybox's own stat applet.
		if ! command -v stat >/dev/null 2>&1; then
			try_optional coreutils-stat "state-file change detection (stat)"
		fi

		# luasec, but only when it is actually needed: inform.lua TLS-wraps the
		# socket for an https:// inform URL and fails with a clear error
		# without it. The UniFi default is plain http on 8080, so installing it
		# unconditionally would spend flash on a feature almost nobody uses --
		# hence the check against the URL openUF will really use: the adopted
		# state file if there is one, otherwise conf.lua's default. (state.json
		# escapes its slashes, which does not affect the scheme match.)
		INFORM_URL=$(sed -n 's/.*"inform_url":"\([^"]*\)".*/\1/p' \
			"$STATE_DIR/state.json" 2>/dev/null | head -1)
		if [ -z "$INFORM_URL" ]; then
			INFORM_URL=$(sed -n 's/.*inform_url[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
				"$INSTALL_DIR/conf.lua" 2>/dev/null | head -1)
		fi
		case "$INFORM_URL" in
			https*) try_optional luasec "TLS for the https:// inform URL" ;;
		esac

		# A full wpad build. BSS Transition and Band Steering need real
		# 802.11k/v support: wpad-basic-* lacks bss_transition entirely and
		# errors with "unknown configuration item 'bss_transition'". Any full
		# build provides it -- checking only for wolfssl/openssl would miss a
		# device already shipping wpad-mbedtls (the OpenWrt 25.12 ath79
		# default) and needlessly swap out a working hostapd, bouncing every
		# SSID on the device for no gain.
		HAVE_WPAD=0
		for pkg in wpad wpad-wolfssl wpad-openssl wpad-mbedtls; do
			if apk info -e "$pkg" >/dev/null 2>&1; then
				HAVE_WPAD=1
				break
			fi
		done
		if [ "$HAVE_WPAD" = "0" ]; then
			echo "Installing a full wpad build (BSS Transition / Band Steering) ..."
			apk add wpad-wolfssl \
				|| apk add wpad-openssl \
				|| apk add wpad-mbedtls \
				|| echo "WARNING: failed to install a full wpad build -- BSS Transition and Band Steering will not function (wpad-basic-* lacks 802.11v support)."
		fi

		# Enable and start services
		"$INIT_SCRIPT" enable 2>/dev/null
		"$INIT_SCRIPT" start

		# Enable lldpd
		if [ -f /etc/init.d/lldpd ]; then
			/etc/init.d/lldpd enable
			/etc/init.d/lldpd start
		else
			echo "WARNING: lldpd init script not found; install lldpd and run:"
			echo "  /etc/init.d/lldpd enable && /etc/init.d/lldpd start"
		fi

		# ── Optional: --bootstrap-adopt ──────────────────────────────────
		# Creates a temporary, non-root SSH account (ubnt/ubnt) matching real
		# Ubiquiti hardware's factory-default login, so first adoption can
		# complete without presetting a root password. Scoped to only ever
		# run `syswrapper.sh set-adopt` (see hook/adopt-shell.sh) and only
		# able to write $STATE_DIR -- no other privilege. Self-locks once the
		# device is adopted and re-enables on factory reset (see
		# inform.lua's M._sync_bootstrap_account). See USAGE.md.
		if [ "$2" = "--bootstrap-adopt" ]; then
			echo "Setting up SSH bootstrap adoption account (ubnt/ubnt) ..."

			ALREADY_ADOPTED=0
			if [ -f "$STATE_DIR/state.json" ] \
				&& grep -q '"adopted":true' "$STATE_DIR/state.json"; then
				ALREADY_ADOPTED=1
			fi

			if [ "$ALREADY_ADOPTED" = "1" ]; then
				echo "  Device is already adopted -- skipping account creation."
			elif grep -q "^ubnt:" /etc/passwd 2>/dev/null; then
				echo "  ubnt account already exists -- leaving as-is."
			else
				# Dedicated group so $STATE_DIR can be made group-writable by
				# the bootstrap account without granting it anything else.
				BA_GID=900
				while grep -q "^[^:]*:[^:]*:$BA_GID:" /etc/group 2>/dev/null; do
					BA_GID=$((BA_GID + 1))
				done
				echo "openuf:x:$BA_GID:" >> /etc/group

				BA_UID=900
				while awk -F: -v id="$BA_UID" \
					'$3==id{f=1} END{exit !f}' /etc/passwd 2>/dev/null; do
					BA_UID=$((BA_UID + 1))
				done

				ADOPT_SHELL="$INSTALL_DIR/hook/adopt-shell.sh"
				chmod +x "$ADOPT_SHELL"

				echo "ubnt:x:$BA_UID:$BA_GID:openuf bootstrap adoption:$STATE_DIR:$ADOPT_SHELL" \
					>> /etc/passwd
				HASH=$(openssl passwd -6 ubnt)
				echo "ubnt:$HASH:::::::" >> /etc/shadow

				chgrp "$BA_GID" "$STATE_DIR"
				chmod g+w "$STATE_DIR"

				# Group-writable directory alone only covers *creating* a new
				# state.json. If one somehow already exists owned by root
				# (e.g. an admin ran `syswrapper.sh reset-inform` by hand
				# before ever using this account), ubnt can't write to it --
				# opening an existing file for writing needs permission on
				# the file itself, not just the directory. Pre-create it
				# group-writable so this works regardless of which side
				# (root or ubnt) writes to it first and thereafter.
				[ -f "$STATE_DIR/state.json" ] || : > "$STATE_DIR/state.json"
				chgrp "$BA_GID" "$STATE_DIR/state.json"
				chmod 664 "$STATE_DIR/state.json"

				# Tell the running daemon this account exists and should be
				# locked/unlocked to track adopted state.
				sed -i 's/bootstrap_adopt_user = nil/bootstrap_adopt_user = "ubnt"/' \
					"$INSTALL_DIR/conf.lua"

				echo "  Created non-root 'ubnt' account (password: ubnt),"
				echo "  restricted to running 'syswrapper.sh set-adopt' only."
				echo "  It self-locks once the device is adopted and"
				echo "  re-enables on factory reset."
			fi
		fi

		echo "Done.  Check status with: logread -e openuf"
		echo ""
		echo "Next steps:"
		echo "  1. If controller is on a different subnet:"
		echo "       syswrapper.sh set-inform http://<controller>:8080/inform"
		echo "  2. Open the UniFi controller → Devices → click Adopt"
		;;

	# ────────────────────────────────────────────────────────────────────────
	uninstall)
		echo "Uninstalling openUF ..."

		# Stop and disable service
		if [ -f "$INIT_SCRIPT" ]; then
			"$INIT_SCRIPT" stop  2>/dev/null
			"$INIT_SCRIPT" disable 2>/dev/null
			rm -f "$INIT_SCRIPT"
		fi

		# Remove symlink
		rm -f "$BIN_LINK"

		# Remove the SSH bootstrap account/group if present (hygiene --
		# symmetric with what install --bootstrap-adopt added, regardless of
		# whether that flag is passed here).
		if grep -q "^ubnt:" /etc/passwd 2>/dev/null; then
			sed -i '/^ubnt:/d' /etc/passwd
			sed -i '/^ubnt:/d' /etc/shadow
			echo "Removed SSH bootstrap account 'ubnt'."
		fi
		if grep -q "^openuf:" /etc/group 2>/dev/null; then
			sed -i '/^openuf:/d' /etc/group
		fi

		# Drop the sysupgrade keep-list entry for conf.lua: that file goes
		# with $INSTALL_DIR (below), and a line pointing at nothing is just
		# litter in a file the user may also hand-edit.
		# $STATE_DIR/ deliberately stays registered. The directory outlives
		# this uninstall by design -- see the message at the end -- so that a
		# later reinstall still finds the authkey, and un-registering it would
		# hand the next sysupgrade precisely the deletion the entry exists to
		# prevent. It is also not necessarily ours: an admin may have added
		# that line by hand before openUF was ever installed. Should the user
		# later remove the directory themselves, the stale line costs nothing
		# -- add_conffiles swallows find's error and returns 0.
		# Fixed-string, whole-line matching -- the mirror of the grep -qxF
		# the install branch adds them with. Not sed: the entry contains the
		# delimiter, and busybox sed's -i is not the same animal as GNU's.
		if [ -f /etc/sysupgrade.conf ]; then
			SU_TMP=$(mktemp) && {
				grep -vxF -e "$INSTALL_DIR/conf.lua" \
					/etc/sysupgrade.conf > "$SU_TMP"
				# grep exits 1 on an empty result, which is a legitimate
				# outcome here (the file held nothing else), so the copy is
				# not conditional on its status.
				cat "$SU_TMP" > /etc/sysupgrade.conf
				rm -f "$SU_TMP"
			}
		fi

		# Remove installed files (leave state dir so authkey is preserved)
		rm -rf "$INSTALL_DIR"

		echo "Done.  State dir $STATE_DIR left intact (remove manually if needed)."
		;;

	# ────────────────────────────────────────────────────────────────────────
	*)
		echo ""
		echo "Usage: $0 <install|uninstall> [--bootstrap-adopt]"
		echo ""
		echo "  install    Copy files to $INSTALL_DIR, create init.d service,"
		echo "             symlink syswrapper.sh to $BIN_LINK"
		echo ""
		echo "  install --bootstrap-adopt"
		echo "             Also create a temporary, non-root SSH account"
		echo "             (ubnt/ubnt) restricted to running 'set-adopt' only,"
		echo "             so first adoption works without presetting a root"
		echo "             password. Self-locks once adopted. See USAGE.md."
		echo ""
		echo "  uninstall  Remove installed files and service."
		echo "             State directory ($STATE_DIR) is preserved."
		echo "             Removes the bootstrap account if present."
		echo ""
		;;
esac
