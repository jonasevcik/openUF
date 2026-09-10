--[[
	openUF heartbeat cost probe.

	Answers "what does one inform actually cost this board?" by building a real
	payload and counting every process it spawns and every file it opens, broken
	down by command and path. Optionally prints the payload itself, so two runs
	can be diffed to show a change is behaviour-neutral.

	It does NOT touch the running daemon. It builds its own payload in a
	throwaway process, so it is safe to run on a live, adopted AP alongside
	openuf -- which is the point: a synthetic fixture cannot tell you how many
	VAPs, sockets or stations this particular board has, and those are what the
	per-radio and per-socket costs multiply by.

	Usage, ON THE DEVICE (cwd must be the install dir, as for inform.lua):
	  scp tools/heartbeat-probe.lua root@<ap>:/tmp/     # or: ssh ... 'cat > /tmp/…'
	  ssh root@<ap> 'cd /opt/openuf && lua /tmp/heartbeat-probe.lua'
	  ssh root@<ap> 'cd /opt/openuf && lua /tmp/heartbeat-probe.lua payload > /tmp/p.json'

	Measurements go to stderr, the payload (with `payload`) to stdout, so the
	two never mix.

	Read the SECOND number, not the first. The first payload of a process warms
	everything that is TTL-cached across heartbeats -- the phy dump, the uplink
	lookup, the LLDP neighbour list -- so it overstates the steady state by
	however much those cost. "steady heartbeat" is what openuf pays every ten
	seconds once it has been up a while.

	This probe measures the BUILD half only. To confirm the daemon is still
	informing, count outbound TCP connections instead -- an AP originates almost
	nothing else, so ActiveOpens rises once per heartbeat:
	  grep -A1 '^Tcp:' /proc/net/snmp | sed -n 2p | cut -d' ' -f6
	Polling `netstat` for a connection to the controller does not work: a POST
	is sub-second and once-a-second sampling misses it on a healthy AP. openuf
	logs nothing on success, so silence in `logread` is not evidence either.
]]--

local MODE = ...

-- Mirror inform.lua's own script entry point. OPENUF_TEST_MODE suppresses the
-- self-executing run() block at the bottom of inform.lua (and announce.lua's
-- broadcast loop, which _populate_net_info would otherwise start).
OPENUF_TEST_MODE = true
pcall(dofile, "lib/lib.lua")
local ok_conf, conf_err = pcall(dofile, "conf.lua")
if not ok_conf then
	io.stderr:write("probe: cannot load conf.lua -- run with cwd = the install "
		.. "dir (e.g. `cd /opt/openuf`): " .. tostring(conf_err) .. "\n")
	os.exit(2)
end
local inform = dofile("inform.lua")
if config and type(config.state_file) == "string" and config.state_file ~= "" then
	inform._state._state_file = config.state_file
end
local ufhw = {uap = dofile("ufmodel/" .. dev.openuf.uap.ufmodel .. ".lua")}
dev.conf.config = config
dev.conf.uap    = dev.openuf and dev.openuf.uap
local st = inform._state.load()
pcall(inform._populate_net_info, st, dev.conf)

-- build_json enforces minimum RSSI inline and will really deauthenticate a
-- client below the threshold. A measurement must not move anyone off the air.
if type(inform._ucihelper) == "table" then
	inform._ucihelper.kick_station = function() return true end
end

-- ─── Counters ───────────────────────────────────────────────────────────────
-- Wrapped around the injectable I/O seams every module already exposes, so the
-- probe needs no cooperation from the code under measurement.

local forks, reads, fork_n, read_n = {}, {}, 0, 0

-- Group by what was asked, not by the exact argv: `iw dev wlan0 station dump`
-- and `iw dev wlan1 station dump` are the same question asked per VAP, and the
-- count is the interesting part.
local function label(cmd)
	local head, next_word = tostring(cmd):match("^%s*(%S+)%s*(%S*)")
	if head == "iw" or head == "ubus" or head == "bridge" or head == "ip" then
		return head .. " " .. next_word
	end
	return head or "?"
end

local function count_cmd(mod, field)
	local orig = type(mod) == "table" and rawget(mod, field)
	if type(orig) ~= "function" then return end
	mod[field] = function(cmd, ...)
		fork_n = fork_n + 1
		local k = label(cmd)
		forks[k] = (forks[k] or 0) + 1
		return orig(cmd, ...)
	end
end

local function count_reads(mod)
	local orig = type(mod) == "table" and rawget(mod, "_read_file")
	if type(orig) ~= "function" then return end
	mod._read_file = function(path, ...)
		read_n = read_n + 1
		-- Collapse per-interface sysfs into one row: 15 reads of
		-- /sys/class/net/<if>/address is one fact about the board, not 15.
		local p = tostring(path):gsub("/sys/class/net/[^/]+/", "/sys/class/net/*/")
		reads[p] = (reads[p] or 0) + 1
		return orig(path, ...)
	end
end

for _, mod in ipairs({inform, inform._sysinfo, inform._ucihelper, inform._lldp,
	inform._rrmscan, inform._switchvlan, inform._firewall}) do
	count_cmd(mod, "_run_cmd")
	count_cmd(mod, "_popen")
	count_reads(mod)
end

-- ─── Measure ────────────────────────────────────────────────────────────────

local ok_cold, cold = pcall(inform.build_json, st, dev.conf, ufhw)
if not ok_cold then
	io.stderr:write("probe: build_json failed (cold): " .. tostring(cold) .. "\n")
	os.exit(1)
end
local cold_forks, cold_reads = fork_n, read_n

forks, reads, fork_n, read_n = {}, {}, 0, 0
local ok_steady, steady = pcall(inform.build_json, st, dev.conf, ufhw)
if not ok_steady then
	io.stderr:write("probe: build_json failed (steady): " .. tostring(steady) .. "\n")
	os.exit(1)
end

local function report(t, title)
	local keys = {}
	for k in pairs(t) do keys[#keys + 1] = k end
	table.sort(keys, function(a, b)
		if t[a] ~= t[b] then return t[a] > t[b] end
		return a < b
	end)
	io.stderr:write("  " .. title .. ":\n")
	for _, k in ipairs(keys) do
		io.stderr:write(string.format("    %-34s %d\n", k, t[k]))
	end
end

io.stderr:write(string.format("cold heartbeat:   %3d forks, %3d file reads  (warms the TTL caches)\n",
	cold_forks, cold_reads))
io.stderr:write(string.format("steady heartbeat: %3d forks, %3d file reads  <-- the per-10s cost\n",
	fork_n, read_n))
report(forks, "forks")
report(reads, "reads")
io.stderr:write(string.format("payload bytes: %d\n", #steady))

if MODE == "payload" then print(steady) end
