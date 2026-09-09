--[[
	Ubiquiti L2 discovery broadcaster (UDP port 10001).

	Sends a TLV-encoded announce packet to 255.255.255.255 every 10 seconds.
	This makes the device visible in UniFi Discover / UBNT-Discovery before
	and after adoption.

	Can be loaded as a module (returns M) or run as a standalone script.
	When run as a script, call M.run(cfg) at the bottom of this file.
]]--

local bit = (function()
	local ok, b = pcall(require, "bit")
	if ok then return b end
	ok, b = pcall(require, "bit32")
	if ok then return b end
	local _l = load or loadstring
	local function _f(e) return _l("return function(a,b) return "..e.." end")() end
	return {band=_f("a&b"), bor=_f("a|b"), lshift=_f("a<<b"), rshift=_f("a>>b")}
end)()

local M = {}

-- Discovery destination addresses and port
M.BROADCAST_ADDR = "255.255.255.255"
M.MULTICAST_ADDR = "233.89.188.1"
M.PORT = 10001

-- Appended to the firmware version strings in the discovery packet. One
-- definition: it used to be typed out twice, in build_packet and in the entry
-- point below, and the two could drift.
M.VERSION_SUFFIX = "-openUF-0.2"

-- TLV type codes for the Ubiquiti discovery protocol
local PKT = {
	HW_ADDR        = 0x01,
	IP_ADDR        = 0x02,
	FWVER_VERBOSE  = 0x03,
	UPTIME         = 0x0a,
	HOSTNAME       = 0x0b,
	PLATFORM       = 0x0c,
	INC_COUNTER    = 0x12,
	HW_ADDR2       = 0x13,
	PLATFORM2      = 0x15,
	FWVER_SHORT    = 0x16,
	FWVER_FACTORY  = 0x1b,
}

-- Build TLV blob for types 0x17–0x1a.
-- 0x17 = IsDefault (1 = unadopted, 0 = adopted) — must reflect actual adoption state.
-- cfg.adopted controls the byte; defaults to unadopted (1) when not set.
local function make_blob_17_1a(adopted)
	return {
		0x17, 0x00, 0x01, adopted and 0x00 or 0x01,
		0x18, 0x00, 0x01, 0x00,
		0x19, 0x00, 0x01, 0x01,
		0x1a, 0x00, 0x01, 0x00,
	}
end

-- Build a complete announce packet as a Lua binary string.
--
-- cfg fields:
--   mac          {byte, ...}  6-element table of MAC bytes
--   ip           {byte, ...}  4-element table of IP bytes
--   hostname     string
--   platform     string       e.g. "U6IW"
--   fw_pre       string       e.g. "U6IW."
--   fw_ver       string       e.g. "6.6.55"
--   fw_buildtime string       e.g. "230801.1200"
--   fw_factoryver string      e.g. "6.5.28"
--   version_suffix string     appended after fw_ver in verbose/short strings
--   uptime       number       seconds since boot
--   counter      number       monotonically increasing send counter
function M.build_packet(cfg)
	-- Outer packet: 2-byte header + 2-byte length field (filled in at end)
	local packet = {0x02, 0x06, 0x00, 0x00}
	local w

	-- 0x02: IP address (MAC + IP concatenated)
	w = ufpkt.init(PKT.IP_ADDR)
	ufpkt.cattbl(w, cfg.mac)
	ufpkt.cattbl(w, cfg.ip)
	ufpkt.finish(w, packet)

	-- 0x01: Hardware address
	w = ufpkt.init(PKT.HW_ADDR)
	ufpkt.cattbl(w, cfg.mac)
	ufpkt.finish(w, packet)

	-- 0x0a: Uptime (32-bit big-endian seconds)
	w = ufpkt.init(PKT.UPTIME)
	ufpkt.cattbl(w, ufpkt.gen4(cfg.uptime or 0))
	ufpkt.finish(w, packet)

	-- 0x0b: Hostname
	w = ufpkt.init(PKT.HOSTNAME)
	ufpkt.catstr(w, cfg.hostname or "openUF")
	ufpkt.finish(w, packet)

	-- 0x0c: Platform string
	w = ufpkt.init(PKT.PLATFORM)
	ufpkt.catstr(w, cfg.platform)
	ufpkt.finish(w, packet)

	-- 0x03: Firmware version verbose
	local suffix = cfg.version_suffix or M.VERSION_SUFFIX
	w = ufpkt.init(PKT.FWVER_VERBOSE)
	ufpkt.catstr(w, cfg.fw_pre)
	ufpkt.catstr(w, cfg.fw_ver)
	ufpkt.catstr(w, suffix .. ".")
	ufpkt.catstr(w, cfg.fw_buildtime)
	ufpkt.finish(w, packet)

	-- 0x16: Firmware version short
	w = ufpkt.init(PKT.FWVER_SHORT)
	ufpkt.catstr(w, cfg.fw_ver)
	ufpkt.catstr(w, suffix)
	ufpkt.finish(w, packet)

	-- 0x15: Platform2 (same as platform)
	w = ufpkt.init(PKT.PLATFORM2)
	ufpkt.catstr(w, cfg.platform)
	ufpkt.finish(w, packet)

	-- Opaque blob 0x17–0x1a (IsDefault reflects adoption state)
	ufpkt.cattbl(packet, make_blob_17_1a(cfg.adopted))

	-- 0x13: Hardware address 2
	w = ufpkt.init(PKT.HW_ADDR2)
	ufpkt.cattbl(w, cfg.mac)
	ufpkt.finish(w, packet)

	-- 0x12: Incrementing counter (32-bit big-endian)
	w = ufpkt.init(PKT.INC_COUNTER)
	ufpkt.cattbl(w, ufpkt.gen4(cfg.counter or 0))
	ufpkt.finish(w, packet)

	-- 0x1b: Factory firmware version
	w = ufpkt.init(PKT.FWVER_FACTORY)
	ufpkt.catstr(w, cfg.fw_factoryver)
	ufpkt.finish(w, packet)

	-- Write full 16-bit packet length (big-endian) into bytes 3–4.
	-- BUG IN ORIGINAL: packet[4] = (len & 0xff) only wrote the low byte.
	-- FIX: write both bytes so packets >= 256 bytes are described correctly.
	local plen = #packet - 4
	packet[3] = bit.band(bit.rshift(plen, 8), 0xff)	-- high byte
	packet[4] = bit.band(plen, 0xff)					-- low byte

	-- Serialise byte table to binary string
	local out = {}
	for _, byte in ipairs(packet) do
		out[#out + 1] = string.char(byte)
	end
	return table.concat(out)
end

-- Read MAC address from sysfs for the given interface.
-- Returns a 6-element byte table or nil on failure.
function M.get_mac(iface)
	iface = iface or "eth0"
	local f = io.open("/sys/class/net/" .. iface .. "/address", "r")
	if not f then return nil end
	local line = f:read("*l"); f:close()
	if not line then return nil end
	local mac = {}
	for byte in line:gmatch("[0-9a-fA-F]+") do
		mac[#mac + 1] = tonumber(byte, 16)
	end
	return #mac == 6 and mac or nil
end

-- Primary IPv4 of one netdev, as a 4-element byte table, or nil if it has none.
local function ipv4_of(iface)
	local out = M._popen("ip -4 addr show dev " .. iface)
	if type(out) ~= "string" then return nil end
	local a, b, c, d = out:match("inet (%d+)%.(%d+)%.(%d+)%.(%d+)")
	if not a then return nil end
	return {tonumber(a), tonumber(b), tonumber(c), tonumber(d)}
end

-- Read primary IPv4 address for the given interface.
-- Returns a 4-element byte table or nil on failure.
--
-- The configured interface (dev.conf.net.lan_cpueth) names the LAN *port* --
-- which is what VLAN provisioning and the port_table need -- but on any AP
-- whose LAN port is enslaved to a bridge (the normal OpenWrt layout: eth1 in
-- br-lan) that port carries no address at all: the L3 address lives on the
-- bridge. Asking only the port yields nil, and the callers' fallbacks are
-- silent and wrong -- announce.run() broadcasts 192.168.1.1 and inform.lua's
-- build_json reports ip "0.0.0.0", which a controller cannot adopt.
-- So: try the port, then the bridge it is a member of, before giving up.
-- The bridge a netdev is enslaved to, or nil. /sys/class/net/<if>/master
-- symlinks to the enslaving device (e.g. "../../../../../virtual/net/br-lan").
local function master_of(iface)
	local m = M._popen("readlink /sys/class/net/" .. iface .. "/master")
	m = type(m) == "string" and m:match("([^/%s]+)%s*$") or nil
	if m and m ~= iface and m ~= "" then return m end
	return nil
end

function M.get_ip(iface)
	iface = iface or "eth0"
	local ip = ipv4_of(iface)
	if ip then return ip end

	-- One hop: the port is a bridge member and the address is on the bridge.
	local master = master_of(iface)
	if master then
		ip = ipv4_of(master)
		if ip then return ip end
	end

	-- Two hops: the port is a VLAN TRUNK, and it is the tagged sub-interface
	-- -- not the trunk itself -- that is enslaved to the bridge. That is the
	-- normal swconfig layout (eth0 -> eth0.1 -> br-lan), and lan_cpueth must
	-- name the trunk there so a pushed VLAN 20 becomes eth0.20 rather than
	-- eth0.1.20. Confirmed on a real TL-WDR3500, where naming the trunk made
	-- every inform report ip 0.0.0.0 until this hop existed.
	local children = M._popen("ls -d /sys/class/net/" .. iface .. ".* 2>/dev/null")
	for line in tostring(children or ""):gmatch("[^\r\n]+") do
		local child = line:match("([^/%s]+)%s*$")
		if child and child ~= iface then
			ip = ipv4_of(child)
			if ip then return ip end
			local cm = master_of(child)
			if cm then
				ip = ipv4_of(cm)
				if ip then return ip end
			end
		end
	end
	return nil
end

-- Injectable: command execution that captures stdout (same seam convention
-- as ucihelper._popen), so tests can feed get_hostname() without a shell.
M._popen = function(cmd)
	local h = io.popen(cmd .. " 2>/dev/null")
	if not h then return "" end
	local s = h:read("*a")
	h:close()
	return s or ""
end

-- Injectable: file reader, same seam convention as ucihelper._read_file.
M._read_file = function(path)
	local f = io.open(path, "r")
	if not f then return nil end
	local s = f:read("*a")
	f:close()
	return s
end

-- The device's real system hostname, or nil when unavailable/empty.
-- Used by the L2-discovery entry point below and by inform.lua's
-- _populate_net_info (the inform payload's top-level "hostname" field --
-- without it every openUF device shows up in the controller as "openUF").
--
-- /proc/sys/kernel/hostname is read FIRST, and the `hostname` command is only
-- a fallback: OpenWrt builds do not necessarily ship a `hostname` applet at
-- all (confirmed on a real Archer C5 running 25.12.5 -- busybox there has no
-- such applet), so the command-only version silently reported every such
-- device to the controller as "openUF" instead of its actual hostname. The
-- proc file is always present on Linux and needs no process spawn.
function M.get_hostname()
	local function clean(s)
		if type(s) ~= "string" then return nil end
		local line = s:match("([^\r\n]+)")           -- first line
		line = line and line:match("^%s*(.-)%s*$")   -- trimmed
		if not line or line == "" then return nil end
		return line
	end
	return clean(M._read_file("/proc/sys/kernel/hostname"))
		or clean(M._popen("hostname"))
end

-- Lazily loaded state module (injectable), for the adopted flag below. The
-- same sibling lookup inform.lua uses; nil when state.lua cannot be found.
M._state = nil
local function state_module()
	if M._state then return M._state end
	for _, p in ipairs({"state.lua", "openuf/state.lua"}) do
		local f = io.open(p, "r")
		if f then
			f:close()
			local ok, mod = pcall(dofile, p)
			if ok and type(mod) == "table" then
				M._state = mod
				return mod
			end
		end
	end
	return nil
end

-- Is the device adopted, per state.json? nil when that cannot be answered (no
-- state module, unreadable file), which callers treat as "leave the flag as it
-- is" -- and it starts out false, the value the packet always carried.
function M.adopted(state_file)
	-- `sm`, not `st`: the state MODULE, whose _state_file seam is being set
	-- here. A local called `st` would read as the state TABLE and trip
	-- test_state's "every field any module writes is registered" scan.
	local sm = state_module()
	if not sm then return nil end
	if state_file then sm._state_file = state_file end
	local ok, s = pcall(sm.load)
	if ok and type(s) == "table" then return s.adopted == true end
	return nil
end

-- Re-read, before each broadcast, the facts that change while the broadcaster
-- runs. The packet used to be built from startup values for the life of the
-- process:
--   • the IsDefault TLV said "unadopted" forever. run() was never handed
--     `adopted`, so the byte make_blob_17_1a's comment insists must reflect
--     adoption state never did;
--   • the IP was whatever the interface had at boot -- wrong after a DHCP
--     renewal or a controller-pushed static address;
--   • uptime counted seconds since the DAEMON started, not since boot.
-- Every read here is a proc file or one `ip` call.
--   cfg.iface       interface to read the IP from (optional)
--   cfg.state_file  state.json path for the adopted flag (optional)
-- A field whose source cannot be read keeps its previous value.
function M._refresh(cfg)
	if cfg.iface then
		local ip = M.get_ip(cfg.iface)
		if ip then cfg.ip = ip end
	end
	local hostname = M.get_hostname()
	if hostname then cfg.hostname = hostname end
	local up = M._read_file("/proc/uptime")
	local secs = up and tonumber(up:match("^(%S+)"))
	if secs then cfg.uptime = math.floor(secs) end
	local adopted = M.adopted(cfg.state_file)
	if adopted ~= nil then cfg.adopted = adopted end
	return cfg
end

-- Start the main announce loop (blocks forever).
-- cfg: same table as build_packet() requires, plus:
--   interval    number  seconds between sends (default 10)
--   iface       string  interface to re-read the IP from each tick
--   state_file  string  state.json path, for the adopted flag
function M.run(cfg)
	local socket = require("socket")

	local udpb = socket.udp()
	-- luasocket creates the underlying OS socket lazily on first real use
	-- (bind/connect/send), not in socket.udp() itself. setoption() before
	-- that point silently no-ops against fd -1, so SO_BROADCAST never
	-- actually gets set and the later setpeername() to a broadcast address
	-- fails with EACCES. Force real socket creation first via a bind.
	udpb:setsockname("*", 0)
	udpb:setoption("broadcast", true)
	-- sendto on the unconnected socket, NOT setpeername + send. At boot this
	-- process comes up before br-lan has an address; setpeername to the
	-- broadcast address then fails with ENETUNREACH -- RETURNING nil rather
	-- than raising -- and the first send raised "calling 'send' on bad self
	-- (udp{connected} expected)", which took the process down. procd
	-- respawned it five seconds later so it healed itself, but every boot
	-- logged a crash. A failed sendto is logged and simply retried next tick.

	local counter  = cfg.counter or 0
	local interval = cfg.interval or 10

	while true do
		counter = counter + 1
		cfg.counter = counter
		-- Counted as before, for the case where /proc/uptime is unreadable;
		-- _refresh replaces it with the real figure whenever it can.
		cfg.uptime = (cfg.uptime or 0) + interval
		M._refresh(cfg)

		local ok, err = udpb:sendto(M.build_packet(cfg), M.BROADCAST_ADDR, M.PORT)
		if not ok then
			io.stderr:write("announce: send failed: " .. tostring(err) .. "\n")
		end
		socket.select(nil, nil, interval)
	end
end

-- ─── Script entry point ───────────────────────────────────────────────────────
-- When run directly (lua announce.lua from the openuf/ directory), load config
-- and start the main loop. When loaded as a module via dofile/require, the
-- caller drives execution.

if not OPENUF_TEST_MODE then
	local ok, err = pcall(function()
		if not ufpkt then dofile("lib/lib.lua") end
		dofile("conf.lua")

		local ufhw = {}
		ufhw.uap = dofile("ufmodel/" .. dev.openuf.uap.ufmodel .. ".lua")

		local iface = dev.conf.net.lan_cpueth or "eth1"
		local mac   = M.get_mac(iface) or {0x24, 0xa4, 0x3c, 0x00, 0xd3, 0xad}
		local ip    = M.get_ip(iface)  or {192, 168, 1, 1}
		local hostname = M.get_hostname() or "openUF"
		-- conf.lua's state_file, honoured here the way inform.lua and
		-- hook/syswrapper.lua honour it, so all three agree on the file.
		local state_file = (config and type(config.state_file) == "string"
			and config.state_file ~= "") and config.state_file or nil

		M.run({
			mac           = mac,
			ip            = ip,
			hostname      = hostname,
			adopted       = M.adopted(state_file) or false,
			iface         = iface,
			state_file    = state_file,
			platform      = ufhw.uap.platform,
			fw_pre        = ufhw.uap.fw.pre,
			fw_ver        = ufhw.uap.fw.ver,
			fw_buildtime  = ufhw.uap.fw.buildtime,
			fw_factoryver = ufhw.uap.fw.factoryver,
			version_suffix = M.VERSION_SUFFIX,
		})
	end)
	if not ok then
		io.stderr:write("announce: " .. tostring(err) .. "\n")
		os.exit(1)
	end
end

return M
