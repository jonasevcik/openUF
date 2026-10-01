-- Tests for install.sh's ensure_full_wpad: a basic wpad/hostapd build is
-- replaced by the full one of the same crypto library, never left behind and
-- never removed without a replacement.
-- Run from project root: lua tests/run_tests.lua
--
-- install.sh is sourced (OPENUF_INSTALL_SOURCE_ONLY) by a real sh with stub
-- apk/opkg scripts first on PATH. The stubs keep the installed set in a file,
-- log every call, and write the full-build marker into a fake hostapd binary
-- when a full build is installed -- the same marker hostapd_full greps for.

local function sh_quote(s) return "'" .. s:gsub("'", "'\\''") .. "'" end

local function write(path, s, mode)
	local f = assert(io.open(path, "w"))
	f:write(s)
	f:close()
	if mode then os.execute("chmod " .. mode .. " " .. sh_quote(path)) end
end

local function read(path)
	local f = io.open(path, "r")
	if not f then return "" end
	local s = f:read("*a")
	f:close()
	return s
end

-- Shared by both stubs: install/remove one package in the state file and
-- keep the fake hostapd in step with what is installed.
local STUB_LIB = [[
D=$(dirname "$0")
echo "$(basename "$0") $*" >> "$D/log"
installed() { grep -qx "$1" "$D/installed"; }
put() {
	grep -vx "$1" "$D/installed" > "$D/i.tmp"; echo "$1" >> "$D/i.tmp"; mv "$D/i.tmp" "$D/installed"
	case "$1" in
		*basic*|*mini) printf 'bss_transition_query_rx\n' > "$D/hostapd" ;;
		wpad*|hostapd*) printf 'bss_transition\nwnm_sleep_mode\n' > "$D/hostapd" ;;
	esac
}
drop() { grep -vx "$1" "$D/installed" > "$D/i.tmp"; mv "$D/i.tmp" "$D/installed"; }
fails() { [ -f "$D/fail_add" ] && grep -qx "$1" "$D/fail_add"; }
]]

local APK_STUB = "#!/bin/sh\n" .. STUB_LIB .. [[
case "$1" in
	info) installed "$3" ;;
	add)
		shift
		for a in "$@"; do case "$a" in !*) ;; *) fails "$a" && exit 1 ;; esac; done
		for a in "$@"; do case "$a" in !*) drop "${a#!}" ;; *) put "$a" ;; esac; done
		;;
	*) exit 1 ;;
esac
]]

local OPKG_STUB = "#!/bin/sh\n" .. STUB_LIB .. [[
case "$1" in
	list-installed) installed "$2" && echo "$2 - 1" ;;
	download) [ -f "$D/fail_download" ] || : > "./$2_1_all.ipk" ;;
	remove) drop "$2" ;;
	install) fails "$2" && exit 1; put "$2" ;;
	*) exit 1 ;;
esac
]]

-- run(manager, installed list, opts) -> rc, output, log, installed-after
local function run(manager, installed, opts)
	opts = opts or {}
	local dir = os.tmpname()
	os.remove(dir)
	assert(os.execute("mkdir -p " .. sh_quote(dir)))
	write(dir .. "/" .. manager, manager == "apk" and APK_STUB or OPKG_STUB, "+x")
	write(dir .. "/installed", table.concat(installed, "\n") .. "\n")
	write(dir .. "/log", "")
	write(dir .. "/hostapd", opts.hostapd or "bss_transition_query_rx\n")
	if opts.fail_add then write(dir .. "/fail_add", table.concat(opts.fail_add, "\n") .. "\n") end
	if opts.fail_download then write(dir .. "/fail_download", "") end

	local h0 = io.popen("pwd")
	local root = h0:read("*l")
	h0:close()
	write(dir .. "/run.sh", ". " .. sh_quote(root .. "/install.sh") .. "\nensure_full_wpad\necho \"rc=$?\"\n")
	local cmd = "cd " .. sh_quote(dir) .. " && PATH=" .. sh_quote(dir) .. ":/usr/bin:/bin"
		.. " OPENUF_INSTALL_SOURCE_ONLY=1 OPENUF_HOSTAPD=" .. sh_quote(dir .. "/hostapd")
		.. " sh run.sh 2>&1"
	local h = io.popen(cmd)
	local out = h:read("*a")
	h:close()
	local log, after = read(dir .. "/log"), read(dir .. "/installed")
	os.execute("rm -rf " .. sh_quote(dir))
	return tonumber(out:match("rc=(%d+)")), out, log, after
end

local function has(list_text, name)
	for line in list_text:gmatch("[^\n]+") do
		if line == name then return true end
	end
	return false
end

-- Only the calls that change something; the stubs also log every query.
local function changes(log)
	local t = {}
	for line in log:gmatch("[^\n]+") do
		if not line:find(" info ", 1, true) and not line:find(" list-installed ", 1, true) then
			t[#t + 1] = line
		end
	end
	return table.concat(t, "\n")
end

return {
	{ name = "apk: basic-mbedtls is replaced by wpad-mbedtls in one transaction", fn = function()
		local rc, out, log, after = run("apk", {"wpad-basic-mbedtls"})
		assert_eq(rc, 0, "a successful swap returns 0\n" .. out)
		assert_eq(changes(log), "apk add wpad-mbedtls !wpad-basic-mbedtls",
			"one apk call that adds the full build and drops the basic one")
		assert_true(has(after, "wpad-mbedtls"), "the full build is installed")
		assert_false(has(after, "wpad-basic-mbedtls"), "the basic build is gone")
	end },

	{ name = "apk: a hostapd that is already full is left alone", fn = function()
		local rc, _, log = run("apk", {"wpad-mbedtls"}, {hostapd = "bss_transition\nwnm_sleep_mode\n"})
		assert_eq(rc, 0, "nothing to do is success")
		assert_eq(changes(log), "", "no package call at all, so no SSID bounces")
	end },

	{ name = "apk: an unlisted full build (mesh) is recognised by the binary", fn = function()
		local rc, _, log = run("apk", {"wpad-mesh-wolfssl"}, {hostapd = "wnm_sleep_mode\n"})
		assert_eq(rc, 0, "full is full")
		assert_eq(changes(log), "", "a mesh build is not replaced")
	end },

	{ name = "apk: bss_transition_* strings alone do not count as full", fn = function()
		-- The real wpad-basic-mbedtls binary has bss_transition_query_rx,
		-- _request_tx and _response_rx: a grep for bss_transition matches it.
		local rc, _, log = run("apk", {"wpad-basic-mbedtls"},
			{hostapd = "bss_transition_query_rx\nbss_transition_request_tx\n"})
		assert_eq(rc, 0, "swapped")
		assert_contains(changes(log), "apk add wpad-mbedtls", "a basic binary is replaced")
	end },

	{ name = "apk: the crypto library follows the basic build", fn = function()
		local _, _, log = run("apk", {"wpad-basic-wolfssl"})
		assert_contains(changes(log), "apk add wpad-wolfssl !wpad-basic-wolfssl", "wolfssl stays wolfssl")
		_, _, log = run("apk", {"hostapd-basic-openssl"})
		assert_contains(changes(log), "apk add hostapd-openssl !hostapd-basic-openssl",
			"a hostapd-only device gets hostapd, not wpad")
		_, _, log = run("apk", {"wpad-basic"})
		assert_contains(changes(log), "apk add wpad-openssl !wpad-basic",
			"internal crypto gets openssl, which lua-openssl already brings")
	end },

	{ name = "apk: a failed swap keeps the basic build and returns non-zero", fn = function()
		local rc, out, _, after = run("apk", {"wpad-basic-mbedtls"}, {fail_add = {"wpad-mbedtls"}})
		assert_eq(rc, 1, "failure is reported")
		assert_true(has(after, "wpad-basic-mbedtls"), "the radios still have a hostapd")
		assert_contains(out, "openUF will not start", "the consequence is said")
	end },

	{ name = "apk: no hostapd package at all installs the full build", fn = function()
		local rc, _, log = run("apk", {})
		assert_eq(rc, 0, "installed")
		assert_eq(changes(log), "apk add wpad-openssl", "a plain add, nothing to drop")
	end },

	{ name = "opkg: download first, then remove basic and install full", fn = function()
		local rc, out, log, after = run("opkg", {"wpad-basic-mbedtls"})
		assert_eq(rc, 0, "a successful swap returns 0\n" .. out)
		assert_eq(changes(log), "opkg download wpad-mbedtls\nopkg remove wpad-basic-mbedtls\nopkg install wpad-mbedtls",
			"the download proves the feed before anything is removed")
		assert_true(has(after, "wpad-mbedtls"), "the full build is installed")
		assert_false(has(after, "wpad-basic-mbedtls"), "the basic build is gone")
	end },

	{ name = "opkg: a failed download removes nothing", fn = function()
		local rc, _, log, after = run("opkg", {"wpad-basic-mbedtls"}, {fail_download = true})
		assert_eq(rc, 1, "failure is reported")
		assert_eq(changes(log), "opkg download wpad-mbedtls", "no remove after a failed download")
		assert_true(has(after, "wpad-basic-mbedtls"), "the basic build stays")
	end },

	{ name = "opkg: a failed install puts the basic build back", fn = function()
		local rc, _, log, after = run("opkg", {"wpad-basic-mbedtls"}, {fail_add = {"wpad-mbedtls"}})
		assert_eq(rc, 1, "failure is reported")
		assert_contains(changes(log), "opkg install wpad-basic-mbedtls", "the old build is reinstalled")
		assert_true(has(after, "wpad-basic-mbedtls"), "the radios still have a hostapd")
	end },
}
