--[[
	Controller-managed system settings: timezone, NTP servers, cron jobs.

	Every full `system_cfg` push carries three blocks openUF did not read
	(first found by the yesrab/openUF fork, 2026-09-15):

	  system.timezone=<POSIX TZ>          (and locale.timezone, the same value)
	  ntpclient.status=enabled
	  ntpclient.<n>.status=enabled / .server=<n>.ubnt.pool.ntp.org   x4
	  cron.status=enabled
	  cron.1.status=enabled / .user=<the pushed ssh user>
	  cron.1.job.1.status=enabled / .schedule=0 4 * * * / .cmd=syswrapper.sh 11k-scan

	The cron job is the interesting one: the controller schedules a nightly
	04:00 (device local time) neighbour scan on every AP through the AP's own
	cron. The verb is added to syswrapper.sh, which asks the running inform
	daemon to scan on its next heartbeat (inform.lua's _maybe_service_scan_request),
	so the scan code stays in one place and the result rides out on that
	heartbeat's scan_table.

	Timezone -> UCI system.@system[0].timezone (the wire string IS a POSIX TZ
	string, which is exactly what that option holds); NTP -> system.ntp.server.
	Both stamp what they replaced (openuf_timezone_orig, openuf_ntp_orig) so
	an operator can see and undo it, and an explicit ntpclient.status=disabled
	puts the original list back. Cron -> a marked block in /etc/crontabs/root,
	rewritten only when it changes and removed when the push stops carrying
	jobs. Only commands openUF actually provides are installed (CRON_COMMANDS):
	a pushed command this build cannot run is logged, never written -- crond
	running an unknown string as root is not "compatibility".

	The pushed cron user is ignored: the account does not exist here and the
	jobs run as root. Nothing is written when the pushed value already matches,
	so a steady stream of identical pushes costs no flash writes.
]]--

local M = {}

-- Injectable seams, as in the other modules.
M._uci  = nil                                            -- mock UCI table; nil = require("uci")
M._exec = function(cmd) return os.execute(cmd) end
M._read_file = function(path)
	local f = io.open(path, "r")
	if not f then return nil end
	local s = f:read("*a")
	f:close()
	return s
end
-- Sibling temp file and rename, like state.save: crond must never see half a file.
M._write_file = function(path, content)
	local tmp = path .. ".tmp"
	local f = io.open(tmp, "w")
	if not f then return false end
	f:write(content)
	f:close()
	local ok = os.rename(tmp, path)
	if not ok then os.remove(tmp) end
	return ok and true or false
end

M.CRONTAB    = "/etc/crontabs/root"
M.BEGIN_MARK = "# openuf-cron-begin -- written by openUF from the controller's cron.* push; edit outside the markers only"
M.END_MARK   = "# openuf-cron-end"

-- Wire command -> what crond runs. Extend only alongside the verb itself.
M.CRON_COMMANDS = {
	["syswrapper.sh 11k-scan"] = "/usr/bin/syswrapper.sh 11k-scan",
}

local function get_uci()
	if M._uci then return M._uci end
	return require("uci")
end

-- ─── Validation ──────────────────────────────────────────────────────────────
-- Everything here is spliced into UCI or a crontab that crond runs as root.

-- A POSIX TZ string: "IST-5:30", "CET-1CEST,M3.5.0,M10.5.0/3", "<+0530>-5:30".
function M.is_valid_tz(s)
	return type(s) == "string" and #s > 0 and #s <= 64
		and s:match("^[%w%+%-:,/%.<>]+$") ~= nil
end

-- A hostname or IPv4 literal.
function M.is_valid_server(s)
	return type(s) == "string" and #s > 0 and #s <= 253
		and s:match("^[%w%.%-]+$") ~= nil and not s:match("^[%.%-]")
end

-- Five crontab fields of digits, '*', ',', '-', '/'.
function M.is_valid_schedule(s)
	if type(s) ~= "string" then return false end
	local n = 0
	for field in s:gmatch("%S+") do
		n = n + 1
		if not field:match("^[%d%*,%-/]+$") then return false end
	end
	return n == 5
end

-- ─── Parsing ─────────────────────────────────────────────────────────────────

-- The three blocks out of a system_cfg blob. Each is nil when the blob does
-- not carry it (a partial push), so apply() touches only what was pushed.
-- Returns nil when none of the three is present at all.
function M.parse(sys_raw)
	if type(sys_raw) ~= "string" then return nil end
	local tz, ntp, cron = nil, nil, nil
	local ntp_rows, cron_rows = {}, {}
	for line in (sys_raw .. "\n"):gmatch("([^\n]*)\n") do
		local k, v = line:match("^([^=]+)=(.*)$")
		if k then
			if k == "system.timezone" or (k == "locale.timezone" and tz == nil) then
				if v ~= "" then tz = v end
			elseif k == "ntpclient.status" then
				ntp = ntp or {servers = {}}
				ntp.enabled = (v == "enabled")
			else
				local i, key = k:match("^ntpclient%.(%d+)%.(.+)$")
				if i then
					ntp = ntp or {servers = {}}
					i = tonumber(i)
					ntp_rows[i] = ntp_rows[i] or {}
					ntp_rows[i][key] = v
				elseif k == "cron.status" then
					cron = cron or {jobs = {}}
					cron.enabled = (v == "enabled")
				else
					local c, rest = k:match("^cron%.(%d+)%.(.+)$")
					if c then
						cron = cron or {jobs = {}}
						c = tonumber(c)
						cron_rows[c] = cron_rows[c] or {jobs = {}}
						local j, jkey = rest:match("^job%.(%d+)%.(.+)$")
						if j then
							j = tonumber(j)
							cron_rows[c].jobs[j] = cron_rows[c].jobs[j] or {}
							cron_rows[c].jobs[j][jkey] = v
						else
							cron_rows[c][rest] = v
						end
					end
				end
			end
		end
	end
	if ntp then
		-- Indices are slot numbers; keep the controller's order.
		local idx = {}
		for i in pairs(ntp_rows) do idx[#idx + 1] = i end
		table.sort(idx)
		for _, i in ipairs(idx) do
			local r = ntp_rows[i]
			if r.status ~= "disabled" and M.is_valid_server(r.server) then
				ntp.servers[#ntp.servers + 1] = r.server
			elseif r.server and r.server ~= "" and r.status ~= "disabled" then
				io.stderr:write("sysconf: ignoring malformed NTP server " .. ("%q"):format(r.server) .. "\n")
			end
		end
		if ntp.enabled == nil then ntp.enabled = (#ntp.servers > 0) end
	end
	if cron then
		local cidx = {}
		for c in pairs(cron_rows) do cidx[#cidx + 1] = c end
		table.sort(cidx)
		for _, c in ipairs(cidx) do
			local tab = cron_rows[c]
			local jidx = {}
			for j in pairs(tab.jobs) do jidx[#jidx + 1] = j end
			table.sort(jidx)
			for _, j in ipairs(jidx) do
				local job = tab.jobs[j]
				cron.jobs[#cron.jobs + 1] = {
					schedule = job.schedule,
					cmd      = job.cmd,
					user     = tab.user,
					enabled  = (tab.status ~= "disabled") and (job.status ~= "disabled"),
				}
			end
		end
		if cron.enabled == nil then cron.enabled = (#cron.jobs > 0) end
	end
	if tz == nil and ntp == nil and cron == nil then return nil end
	return {timezone = tz, ntp = ntp, cron = cron}
end

-- ─── Apply ───────────────────────────────────────────────────────────────────

local function to_list(v)
	if type(v) == "table" then return v end
	if type(v) == "string" and v ~= "" then
		local out = {}
		for item in v:gmatch("%S+") do out[#out + 1] = item end
		return out
	end
	return {}
end

local function same_list(a, b)
	if #a ~= #b then return false end
	for i = 1, #a do if tostring(a[i]) ~= tostring(b[i]) then return false end end
	return true
end

-- The first `config system` section's name (usually anonymous: "@system[0]"
-- to uci(1), an internal cfgXXXX name to libuci).
local function system_section(cursor)
	local sec
	cursor:foreach("system", "system", function(s)
		if not sec then sec = s[".name"] end
	end)
	return sec
end

-- UCI system.@system[0].timezone <- the pushed POSIX string. Written only when
-- it differs; the original is stamped once as openuf_timezone_orig. zonename
-- (the Olson name LuCI keeps alongside the string it derived) is moved to
-- openuf_zonename_orig, since it now names a different zone. Returns true
-- when something was written.
function M.apply_timezone(tz)
	if not M.is_valid_tz(tz) then
		if tz ~= nil then
			io.stderr:write("sysconf: ignoring malformed timezone " .. ("%q"):format(tostring(tz)) .. "\n")
		end
		return false
	end
	local cursor = get_uci().cursor()
	local sec = system_section(cursor)
	if not sec then return false end
	local cur = cursor:get("system", sec, "timezone")
	if cur == tz then return false end
	if not cursor:get("system", sec, "openuf_timezone_orig") then
		cursor:set("system", sec, "openuf_timezone_orig", cur or "UTC")
	end
	cursor:set("system", sec, "timezone", tz)
	local zn = cursor:get("system", sec, "zonename")
	if zn then
		if not cursor:get("system", sec, "openuf_zonename_orig") then
			cursor:set("system", sec, "openuf_zonename_orig", zn)
		end
		cursor:delete("system", sec, "zonename")
	end
	cursor:commit("system")
	io.stderr:write(("sysconf: timezone %s -> %s (controller)\n"):format(tostring(cur), tz))
	M._exec("/etc/init.d/system reload >/dev/null 2>&1")
	return true
end

-- UCI system.ntp.server <- the pushed list, when the block is enabled and
-- names at least one valid server; the board's own list is stamped once as
-- openuf_ntp_orig (with openuf_ntp_managed as the marker, since an empty
-- original cannot be stored as a list). An explicit ntpclient.status=disabled
-- puts the original back and drops the stamps. Absence of the block does
-- nothing -- partial pushes exist. Returns true when something was written.
function M.apply_ntp(ntp)
	if type(ntp) ~= "table" then return false end
	local cursor = get_uci().cursor()
	if not cursor:get("system", "ntp") then return false end
	local cur = to_list(cursor:get("system", "ntp", "server"))
	if ntp.enabled and #ntp.servers > 0 then
		if same_list(cur, ntp.servers) then return false end
		if not cursor:get("system", "ntp", "openuf_ntp_managed") then
			if #cur > 0 then cursor:set("system", "ntp", "openuf_ntp_orig", cur) end
			cursor:set("system", "ntp", "openuf_ntp_managed", "1")
		end
		cursor:set("system", "ntp", "server", ntp.servers)
		cursor:commit("system")
		io.stderr:write("sysconf: NTP servers <- controller: " .. table.concat(ntp.servers, " ") .. "\n")
		M._exec("/etc/init.d/sysntpd restart >/dev/null 2>&1")
		return true
	end
	if ntp.enabled == false then
		if not cursor:get("system", "ntp", "openuf_ntp_managed") then return false end
		local orig = to_list(cursor:get("system", "ntp", "openuf_ntp_orig"))
		if #orig > 0 then
			cursor:set("system", "ntp", "server", orig)
		else
			cursor:delete("system", "ntp", "server")
		end
		cursor:delete("system", "ntp", "openuf_ntp_orig")
		cursor:delete("system", "ntp", "openuf_ntp_managed")
		cursor:commit("system")
		io.stderr:write("sysconf: NTP servers restored to the board's own (controller disabled ntpclient)\n")
		M._exec("/etc/init.d/sysntpd restart >/dev/null 2>&1")
		return true
	end
	return false
end

-- Everything in the crontab outside openUF's marked block, normalised to end
-- with a newline (or be empty).
local function strip_managed(text)
	local out, skipping = {}, false
	for line in (text .. "\n"):gmatch("([^\n]*)\n") do
		if line == M.BEGIN_MARK then
			skipping = true
		elseif line == M.END_MARK then
			skipping = false
		elseif not skipping then
			out[#out + 1] = line
		end
	end
	-- Drop the trailing empty element gmatch's sentinel newline produced.
	while #out > 0 and out[#out] == "" do out[#out] = nil end
	if #out == 0 then return "" end
	return table.concat(out, "\n") .. "\n"
end

-- The controller's cron jobs, as a marked block in the root crontab. Only
-- commands in CRON_COMMANDS are installed; anything else is logged and
-- skipped. Rewritten only when the resulting file differs, and crond told
-- when it does. cron.status=disabled, or no installable job, removes the
-- block. Returns true when the file was rewritten.
function M.apply_cron(cron)
	if type(cron) ~= "table" then return false end
	local lines = {}
	if cron.enabled then
		for _, job in ipairs(cron.jobs or {}) do
			if job.enabled ~= false then
				local runs = M.CRON_COMMANDS[job.cmd]
				if not runs then
					io.stderr:write("sysconf: cron job not installed -- not a command this build provides: "
						.. ("%q"):format(tostring(job.cmd)) .. "\n")
				elseif not M.is_valid_schedule(job.schedule) then
					io.stderr:write("sysconf: cron job not installed -- malformed schedule "
						.. ("%q"):format(tostring(job.schedule)) .. "\n")
				else
					lines[#lines + 1] = job.schedule .. " " .. runs
				end
			end
		end
	end
	local existing = M._read_file(M.CRONTAB) or ""
	local kept = strip_managed(existing)
	local new = kept
	if #lines > 0 then
		new = kept .. M.BEGIN_MARK .. "\n" .. table.concat(lines, "\n") .. "\n" .. M.END_MARK .. "\n"
	end
	if new == existing then return false end
	if not M._write_file(M.CRONTAB, new) then
		io.stderr:write("sysconf: cannot write " .. M.CRONTAB .. "\n")
		return false
	end
	if #lines > 0 then
		io.stderr:write(("sysconf: %d controller cron job(s) installed in %s\n"):format(#lines, M.CRONTAB))
		-- crond does not start on a board whose crontab dir was empty at boot,
		-- and is not necessarily enabled; both are one restart + enable away.
		M._exec("/etc/init.d/cron enable >/dev/null 2>&1")
	else
		io.stderr:write("sysconf: controller cron jobs removed from " .. M.CRONTAB .. "\n")
	end
	M._exec("/etc/init.d/cron restart >/dev/null 2>&1")
	return true
end

-- One call from the setparam path. Each part is pcall'd on its own: a full
-- overlay or a missing init script must cost one part, not the other two.
function M.apply(parsed)
	local r = {}
	if type(parsed) ~= "table" then return r end
	local ok, res
	ok, res = pcall(M.apply_timezone, parsed.timezone); r.timezone = ok and res or false
	if not ok then io.stderr:write("sysconf: timezone: " .. tostring(res) .. "\n") end
	ok, res = pcall(M.apply_ntp, parsed.ntp);           r.ntp = ok and res or false
	if not ok then io.stderr:write("sysconf: ntp: " .. tostring(res) .. "\n") end
	ok, res = pcall(M.apply_cron, parsed.cron);         r.cron = ok and res or false
	if not ok then io.stderr:write("sysconf: cron: " .. tostring(res) .. "\n") end
	return r
end

return M
