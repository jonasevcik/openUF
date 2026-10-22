--[[
	ftinterop.lua -- 802.11r fast roaming between openUF and genuine UniFi APs.

	Off by default (conf.lua `unifi_ft_interop`). Stock OpenWrt hostapd and
	UniFi's patched hostapd use the same FT key hierarchy and the same AES-SIV
	protected RRB payloads, but frame them differently: UniFi inserts the
	source and destination AP addresses (12 bytes) after the RRB type. The
	rrb-unifi translator (https://github.com/d-malinowski/unifi-openwrt-roaming)
	converts between the two
	framings on a veth pair: hostapd's ft_iface is one end (vft0), the
	translator holds the other end and br-lan.

	With the framing handled outside openUF, what is left is config, and
	this module supplies the four places where openUF's defaults differ from
	what a UniFi peer needs:

	  * mobility domain: UniFi firmware's own derivation, the first two
	    bytes of SHA1("salt" .. SSID zero-padded to 32 bytes). Verified
	    against a live U7 Lite (UniFi 8.7.11) by comparing its hostapd
	    config's mobility_domain; for example SSID "corp" -> 5de5.
	    openUF's default hash deliberately differs, so that clients never
	    try FT towards a UniFi AP without the translator.
	  * ft_psk_generate_local=0. OpenWrt defaults it to 1 for PSK and then
	    writes no key holders, so a UniFi AP pulling a PMK-R1 from this AP
	    gets no answer.
	  * nas_identifier = this BSS's BSSID without colons, the same R0KH-ID
	    convention UniFi firmware uses ($bssid). OpenWrt sets none.
	  * explicit key holders for every UniFi peer BSS, listed by the
	    translator's setup tool in /etc/config/rrb-unifi
	    (`list ft_peer '<bssid>,<r0kh-id>'`), keyed with the controller's
	    iapp_key. pmk_r1_push skips wildcard entries, so a peer only gets
	    pushes when it is listed.

	And hostapd's ft_iface, set only when the translator's veth end exists:
	an ft_iface that does not exist makes hostapd fail the BSS, while without
	it the WLAN still works and only fast roaming to UniFi peers is lost.

	reassociation_deadline is left at OpenWrt's default (openUF writes
	UniFi's 3000 TU otherwise), so an interop AP keeps the timing the
	translator was validated with.
]]

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

M.RRB_CONFIG     = "rrb-unifi"
M.DEFAULT_FT_IFACE = "vft0"

-- Injectable seams.
M._read_file = util.read_file
M._log = function(msg) io.stderr:write("openuf: ftinterop: " .. msg .. "\n") end

-- ─── SHA1 (pure Lua, 32-bit words through util.bit) ──────────────────────────

local TWO32 = 4294967296

-- Lowercase hex SHA1 of msg. Every intermediate sum is reduced mod 2^32 by
-- hand, so the result does not depend on which bit library util.bit() found
-- (LuaBitOp returns signed words, bit32 unsigned ones).
function M.sha1(msg)
	local bit = util.bit()
	local band, bor, bxor = bit.band, bit.bor, bit.bxor
	local lshift, rshift = bit.lshift, bit.rshift
	local function u(x) return x % TWO32 end
	local function rol(x, n) return u(bor(lshift(x, n), rshift(u(x), 32 - n))) end
	local function bnot(x) return TWO32 - 1 - u(x) end

	local len = #msg
	msg = msg .. string.char(0x80)
	msg = msg .. string.rep(string.char(0), (56 - #msg % 64) % 64)
	local bits = len * 8
	local tail = {}
	for i = 8, 1, -1 do
		tail[i] = string.char(bits % 256)
		bits = math.floor(bits / 256)
	end
	msg = msg .. table.concat(tail)

	local h0, h1, h2, h3, h4 =
		0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
	local w = {}
	for chunk = 1, #msg, 64 do
		for i = 0, 15 do
			local a, b, c, d = msg:byte(chunk + i * 4, chunk + i * 4 + 3)
			w[i] = ((a * 256 + b) * 256 + c) * 256 + d
		end
		for i = 16, 79 do
			w[i] = rol(bxor(bxor(w[i - 3], w[i - 8]), bxor(w[i - 14], w[i - 16])), 1)
		end
		local a, b, c, d, e = h0, h1, h2, h3, h4
		for i = 0, 79 do
			local f, k
			if i < 20 then
				f, k = bor(band(b, c), band(bnot(b), d)), 0x5A827999
			elseif i < 40 then
				f, k = bxor(bxor(b, c), d), 0x6ED9EBA1
			elseif i < 60 then
				f, k = bor(bor(band(b, c), band(b, d)), band(c, d)), 0x8F1BBCDC
			else
				f, k = bxor(bxor(b, c), d), 0xCA62C1D6
			end
			local t = u(rol(a, 5) + u(f) + e + k + w[i])
			e, d, c, b, a = d, c, rol(b, 30), a, t
		end
		h0, h1, h2 = u(h0 + a), u(h1 + b), u(h2 + c)
		h3, h4 = u(h3 + d), u(h4 + e)
	end
	-- %08x would raise for words >= 2^31 on OpenWrt's LNUM Lua: format each
	-- word as two 16-bit halves instead.
	local out = {}
	for _, h in ipairs({h0, h1, h2, h3, h4}) do
		out[#out + 1] = string.format("%04x%04x", math.floor(h / 65536), h % 65536)
	end
	return table.concat(out)
end

-- UniFi firmware's mobility domain for an SSID (4 hex chars).
function M.mobility_domain(ssid)
	ssid = tostring(ssid or "")
	if #ssid < 32 then ssid = ssid .. string.rep(string.char(0), 32 - #ssid) end
	return M.sha1("salt" .. ssid):sub(1, 4)
end

-- ─── translator config ───────────────────────────────────────────────────────

-- The UniFi peer BSSes from /etc/config/rrb-unifi, as
-- {{bssid = "aa:bb:..", r0kh_id = "aabb.."}, ...}. Malformed entries are
-- dropped with a log line rather than written into hostapd's config.
function M.peers(cursor)
	local raw = cursor and cursor:get(M.RRB_CONFIG, "main", "ft_peer")
	if type(raw) == "string" then raw = {raw} end
	local out = {}
	for _, e in ipairs(type(raw) == "table" and raw or {}) do
		local bssid, r0 = tostring(e):match("^%s*([^,%s]+)%s*,%s*([^,%s]+)%s*$")
		bssid = bssid and bssid:lower()
		if util.is_mac(bssid) and r0 and r0:match("^[%w%-%._:]+$") and #r0 <= 48 then
			out[#out + 1] = {bssid = bssid, r0kh_id = r0}
		else
			M._log("ignoring malformed ft_peer entry " .. string.format("%q", tostring(e)))
		end
	end
	return out
end

-- The ft_iface hostapd should use, or nil when it does not exist (yet).
function M.ft_iface(cursor)
	local name = cursor and cursor:get(M.RRB_CONFIG, "main", "ft_iface")
	if type(name) ~= "string" or name == "" then name = M.DEFAULT_FT_IFACE end
	if not util.valid_ifname(name) then return nil end
	if not M._read_file("/sys/class/net/" .. name .. "/ifindex") then return nil end
	return name
end

-- ─── the UCI options ─────────────────────────────────────────────────────────

-- Rewrite one FT VAP's `extra` table (ucihelper.apply_config's option set)
-- for UniFi interop. `vap` is the parsed controller VAP, `bssid` this BSS's
-- address when known (nil: no nas_identifier is written, and the next push
-- fills it in once the interface is up). `cursor` reads /etc/config/rrb-unifi.
function M.apply(extra, vap, bssid, cursor, delete)
	extra.mobility_domain = M.mobility_domain(vap.ssid)
	extra.ft_psk_generate_local = "0"
	extra.reassociation_deadline = delete
	if util.is_mac(bssid) then
		extra.nasid = bssid:lower():gsub(":", "")
	else
		M._log(string.format("%s on %s: BSSID not known yet, no nas_identifier this push",
			tostring(vap.ssid), tostring(vap.radio)))
	end

	if vap.iapp_key then
		local key = vap.iapp_key
		local r0kh, r1kh = {}, {}
		for _, p in ipairs(M.peers(cursor)) do
			r0kh[#r0kh + 1] = p.bssid .. "," .. p.r0kh_id .. "," .. key
			r1kh[#r1kh + 1] = p.bssid .. "," .. p.bssid .. "," .. key
		end
		r0kh[#r0kh + 1] = "ff:ff:ff:ff:ff:ff,*," .. key
		r1kh[#r1kh + 1] = "00:00:00:00:00:00,00:00:00:00:00:00," .. key
		extra.r0kh, extra.r1kh = r0kh, r1kh
		if #r0kh == 1 then
			M._log("no ft_peer in /etc/config/" .. M.RRB_CONFIG
				.. ": UniFi peers can pull keys, but none get pushed")
		end
	else
		-- Without the controller's key OpenWrt derives one from the
		-- passphrase, which no UniFi AP shares.
		M._log(string.format("%s: the controller sent no iapp_key, "
			.. "fast roaming to UniFi APs will not work", tostring(vap.ssid)))
	end

	local ifn = M.ft_iface(cursor)
	if ifn then
		extra.hostapd_bss_options = {"ft_iface=" .. ifn}
	else
		extra.hostapd_bss_options = delete
		M._log("ft_iface not present, hostapd stays on the bridge: "
			.. "fast roaming to UniFi APs needs the rrb-unifi translator")
	end
	return extra
end

return M
