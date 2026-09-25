-- Tests for openuf/sysconf.lua (timezone, NTP, cron from the controller).
-- Run from project root: lua tests/run_tests.lua

OPENUF_TEST_MODE = true
local sysconf = dofile("openuf/sysconf.lua")

-- A UCI mock with the same contract libuci-lua has for what this module
-- uses: get() of a list option returns a table; set() with a table writes a
-- list; foreach() yields sections with .name/.type.
local function mock_uci(db, commits)
	local cursor = {}
	function cursor:get(c, s, o)
		local sec = db[c] and db[c][s]
		if not sec then return nil end
		if o == nil then return sec[".type"] end
		return sec[o]
	end
	function cursor:set(c, s, o, v)
		db[c] = db[c] or {}
		db[c][s] = db[c][s] or {[".name"] = s, [".type"] = s}
		if type(v) == "table" then
			local l = {}
			for i, x in ipairs(v) do l[i] = tostring(x) end
			v = l
		else
			v = tostring(v)
		end
		db[c][s][o] = v
		return true
	end
	function cursor:delete(c, s, o)
		if db[c] and db[c][s] then db[c][s][o] = nil end
		return true
	end
	function cursor:commit(c) commits[#commits + 1] = c; return true end
	function cursor:foreach(c, t, fn)
		local names = {}
		for name, sec in pairs(db[c] or {}) do if sec[".type"] == t then names[#names + 1] = name end end
		table.sort(names)
		for _, name in ipairs(names) do fn(db[c][name]) end
	end
	return {cursor = function() return cursor end}
end

local function fresh(db)
	local commits, cmds, files = {}, {}, {}
	sysconf._uci = mock_uci(db, commits)
	sysconf._exec = function(cmd) cmds[#cmds + 1] = cmd; return 0 end
	sysconf.CRONTAB = "/tmp/openuf_test_crontab"
	sysconf._read_file = function(p) return files[p] end
	sysconf._write_file = function(p, c) files[p] = c; return true end
	return commits, cmds, files
end

local function with_stderr(fn)
	local buf, real = {}, io.stderr
	io.stderr = {write = function(_, ...) for _, s in ipairs({...}) do buf[#buf + 1] = s end end}
	local ok, err = pcall(fn)
	io.stderr = real
	if not ok then error(err, 0) end
	return table.concat(buf)
end

-- The three blocks in the shape a real push carries them (the fork's
-- capture, user renamed), plus two decoys and a duplicate timezone.
local CAPTURE = table.concat({
	"system.timezone=IST-5:30",
	"locale.timezone=IST-5:30",
	"ntpclient.status=enabled",
	"ntpclient.1.status=enabled", "ntpclient.1.server=0.ubnt.pool.ntp.org",
	"ntpclient.2.status=enabled", "ntpclient.2.server=1.ubnt.pool.ntp.org",
	"ntpclient.3.status=enabled", "ntpclient.3.server=2.ubnt.pool.ntp.org",
	"ntpclient.4.status=enabled", "ntpclient.4.server=3.ubnt.pool.ntp.org",
	"cron.status=enabled",
	"cron.1.status=enabled",
	"cron.1.user=pusheduser",
	"cron.1.job.1.status=enabled",
	"cron.1.job.1.schedule=0 4 * * *",
	"cron.1.job.1.cmd=syswrapper.sh 11k-scan",
	"radio.1.channel=6",
	"aaa.1.wpa.psk=hunter2",
}, "\n") .. "\n"

local function system_db(tz, zonename, servers)
	return {
		system = {
			cfg01 = {[".name"] = "cfg01", [".type"] = "system", hostname = "U6_IW",
			         timezone = tz, zonename = zonename},
			ntp   = {[".name"] = "ntp", [".type"] = "timeserver", server = servers},
		},
	}
end

return {
	{
		name = "sysconf: parse reads the three blocks out of a real capture and nothing else",
		fn = function()
			local p = sysconf.parse(CAPTURE)
			assert_eq(p.timezone, "IST-5:30", "timezone")
			assert_true(p.ntp.enabled, "ntp enabled")
			assert_eq(table.concat(p.ntp.servers, ","),
				"0.ubnt.pool.ntp.org,1.ubnt.pool.ntp.org,2.ubnt.pool.ntp.org,3.ubnt.pool.ntp.org", "servers in slot order")
			assert_true(p.cron.enabled, "cron enabled")
			assert_eq(#p.cron.jobs, 1, "one job")
			assert_eq(p.cron.jobs[1].schedule, "0 4 * * *", "schedule")
			assert_eq(p.cron.jobs[1].cmd, "syswrapper.sh 11k-scan", "cmd")
			assert_eq(p.cron.jobs[1].user, "pusheduser", "user carried (ignored by apply)")
			assert_true(p.cron.jobs[1].enabled, "job enabled")
		end
	},
	{
		name = "sysconf: parse returns nil for a blob without the blocks, and partial blocks stay nil",
		fn = function()
			assert_nil(sysconf.parse("radio.1.channel=6\naaa.1.ssid=x\n"), "nothing relevant")
			assert_nil(sysconf.parse(nil), "nil input")
			local p = sysconf.parse("ntpclient.status=disabled\n")
			assert_nil(p.timezone, "no timezone")
			assert_nil(p.cron, "no cron")
			assert_false(p.ntp.enabled, "ntp explicitly off")
			assert_eq(#p.ntp.servers, 0, "no servers")
		end
	},
	{
		name = "sysconf: parse drops malformed servers and disabled slots, keeps the order",
		fn = function()
			local out = with_stderr(function()
				local p = sysconf.parse("ntpclient.status=enabled\nntpclient.2.server=b.example\n"
					.. "ntpclient.1.server=a.example\nntpclient.3.status=disabled\nntpclient.3.server=c.example\n"
					.. "ntpclient.4.server=bad host;rm -rf /\n")
				assert_eq(table.concat(p.ntp.servers, ","), "a.example,b.example", "ordered, filtered")
			end)
			assert_contains(out, "malformed NTP server", "the bad one is logged")
		end
	},
	{
		name = "sysconf: validators refuse what must never reach UCI or a crontab",
		fn = function()
			assert_true(sysconf.is_valid_tz("IST-5:30"), "IST")
			assert_true(sysconf.is_valid_tz("CET-1CEST,M3.5.0,M10.5.0/3"), "CET rule")
			assert_true(sysconf.is_valid_tz("<+0530>-5:30"), "angle-bracket form")
			assert_false(sysconf.is_valid_tz("IST-5:30'; reboot"), "quote")
			assert_false(sysconf.is_valid_tz(""), "empty")
			assert_true(sysconf.is_valid_server("0.ubnt.pool.ntp.org"), "hostname")
			assert_true(sysconf.is_valid_server("192.0.2.1"), "ipv4")
			assert_false(sysconf.is_valid_server("a b"), "space")
			assert_false(sysconf.is_valid_server("-x"), "leading dash")
			assert_true(sysconf.is_valid_schedule("0 4 * * *"), "five fields")
			assert_true(sysconf.is_valid_schedule("*/15 0-6 1,15 * 1-5"), "ranges and steps")
			assert_false(sysconf.is_valid_schedule("0 4 * *"), "four fields")
			assert_false(sysconf.is_valid_schedule("0 4 * * * root"), "six fields")
			assert_false(sysconf.is_valid_schedule("@daily"), "nicknames")
		end
	},
	{
		name = "sysconf: apply_timezone is a no-op when UCI already has the pushed string",
		fn = function()
			local db = system_db("IST-5:30", "Asia/Kolkata", nil)
			local commits, cmds = fresh(db)
			assert_false(sysconf.apply_timezone("IST-5:30"), "nothing to do")
			assert_eq(#commits, 0, "no commit")
			assert_eq(#cmds, 0, "no reload")
			assert_eq(db.system.cfg01.zonename, "Asia/Kolkata", "zonename untouched")
		end
	},
	{
		name = "sysconf: apply_timezone writes a different string, stamps the originals, retires zonename, reloads",
		fn = function()
			local db = system_db("UTC", "UTC", nil)
			local commits, cmds = fresh(db)
			local out = with_stderr(function()
				assert_true(sysconf.apply_timezone("IST-5:30"), "changed")
			end)
			assert_eq(db.system.cfg01.timezone, "IST-5:30", "timezone written")
			assert_eq(db.system.cfg01.openuf_timezone_orig, "UTC", "original stamped")
			assert_nil(db.system.cfg01.zonename, "stale Olson name removed")
			assert_eq(db.system.cfg01.openuf_zonename_orig, "UTC", "and stamped")
			assert_eq(commits[1], "system", "committed")
			assert_contains(cmds[1], "/etc/init.d/system reload", "reloaded")
			assert_contains(out, "UTC -> IST-5:30", "logged")
			-- A second change keeps the FIRST original.
			sysconf.apply_timezone("CET-1")
			assert_eq(db.system.cfg01.openuf_timezone_orig, "UTC", "first original kept")
			-- Malformed: refused, nothing written.
			local n = #commits
			out = with_stderr(function() assert_false(sysconf.apply_timezone("X'; reboot"), "refused") end)
			assert_eq(#commits, n, "no commit for a malformed value")
			assert_contains(out, "malformed timezone", "said so")
		end
	},
	{
		name = "sysconf: apply_ntp replaces the server list once, stamps the board's own, restarts sysntpd",
		fn = function()
			local db = system_db("IST-5:30", nil, {"0.openwrt.pool.ntp.org", "1.openwrt.pool.ntp.org"})
			local commits, cmds = fresh(db)
			local ntp = {enabled = true, servers = {"0.ubnt.pool.ntp.org", "1.ubnt.pool.ntp.org"}}
			with_stderr(function() assert_true(sysconf.apply_ntp(ntp), "changed") end)
			assert_eq(table.concat(db.system.ntp.server, ","), "0.ubnt.pool.ntp.org,1.ubnt.pool.ntp.org", "list replaced")
			assert_eq(table.concat(db.system.ntp.openuf_ntp_orig, ","), "0.openwrt.pool.ntp.org,1.openwrt.pool.ntp.org", "original stamped")
			assert_eq(db.system.ntp.openuf_ntp_managed, "1", "marker")
			assert_contains(cmds[#cmds], "sysntpd restart", "restarted")
			assert_false(sysconf.apply_ntp(ntp), "same list again: no-op")
			assert_eq(#commits, 1, "one commit in total")
			-- Explicit disable puts the board's own list back and clears the stamps.
			with_stderr(function() assert_true(sysconf.apply_ntp({enabled = false, servers = {}}), "restored") end)
			assert_eq(table.concat(db.system.ntp.server, ","), "0.openwrt.pool.ntp.org,1.openwrt.pool.ntp.org", "original back")
			assert_nil(db.system.ntp.openuf_ntp_orig, "stamp gone")
			assert_nil(db.system.ntp.openuf_ntp_managed, "marker gone")
			assert_false(sysconf.apply_ntp({enabled = false, servers = {}}), "disable when not managed: no-op")
		end
	},
	{
		name = "sysconf: apply_ntp with no original list deletes the option on restore, and ignores an empty enabled block",
		fn = function()
			local db = system_db("IST-5:30", nil, nil)
			fresh(db)
			with_stderr(function() sysconf.apply_ntp({enabled = true, servers = {"a.example"}}) end)
			assert_nil(db.system.ntp.openuf_ntp_orig, "nothing to stamp")
			assert_eq(db.system.ntp.openuf_ntp_managed, "1", "but managed")
			with_stderr(function() sysconf.apply_ntp({enabled = false, servers = {}}) end)
			assert_nil(db.system.ntp.server, "option removed, as it was")
			assert_false(sysconf.apply_ntp({enabled = true, servers = {}}), "enabled with no valid server: nothing")
		end
	},
	{
		name = "sysconf: apply_cron installs the allowed job between markers, keeps the operator's lines, enables and restarts crond",
		fn = function()
			local commits, cmds, files = fresh(system_db("IST-5:30", nil, nil))
			files[sysconf.CRONTAB] = "# mine\n30 3 * * * /usr/bin/backup.sh\n"
			local cron = sysconf.parse(CAPTURE).cron
			local out = with_stderr(function() assert_true(sysconf.apply_cron(cron), "written") end)
			local t = files[sysconf.CRONTAB]
			assert_contains(t, "# mine\n30 3 * * * /usr/bin/backup.sh\n", "operator lines kept")
			assert_contains(t, sysconf.BEGIN_MARK .. "\n0 4 * * * /usr/bin/syswrapper.sh 11k-scan\n" .. sysconf.END_MARK .. "\n",
				"managed block with the mapped command")
			assert_contains(table.concat(cmds, "\n"), "/etc/init.d/cron enable", "enabled")
			assert_contains(cmds[#cmds], "/etc/init.d/cron restart", "restarted")
			assert_contains(out, "1 controller cron job(s) installed", "logged")
			-- Same push again: byte-identical, so no write and no restart.
			local n = #cmds
			assert_false(sysconf.apply_cron(cron), "idempotent")
			assert_eq(#cmds, n, "no restart when unchanged")
		end
	},
	{
		name = "sysconf: apply_cron refuses commands this build does not provide and malformed schedules",
		fn = function()
			local _, cmds, files = fresh(system_db("IST-5:30", nil, nil))
			local cron = {enabled = true, jobs = {
				{schedule = "0 4 * * *", cmd = "rm -rf /", enabled = true},
				{schedule = "0 4 * * * root", cmd = "syswrapper.sh 11k-scan", enabled = true},
				{schedule = "0 5 * * *", cmd = "syswrapper.sh 11k-scan", enabled = false},
			}}
			local out = with_stderr(function() assert_false(sysconf.apply_cron(cron), "nothing installable") end)
			assert_nil(files[sysconf.CRONTAB], "no file written")
			assert_eq(#cmds, 0, "crond not touched")
			assert_contains(out, 'not a command this build provides: "rm -rf /"', "unknown cmd named")
			assert_contains(out, "malformed schedule", "bad schedule named")
		end
	},
	{
		name = "sysconf: apply_cron removes the managed block when the push stops carrying jobs",
		fn = function()
			local _, cmds, files = fresh(system_db("IST-5:30", nil, nil))
			files[sysconf.CRONTAB] = "# mine\n" .. sysconf.BEGIN_MARK .. "\n0 4 * * * /usr/bin/syswrapper.sh 11k-scan\n"
				.. sysconf.END_MARK .. "\n"
			local out = with_stderr(function()
				assert_true(sysconf.apply_cron({enabled = false, jobs = {}}), "rewritten")
			end)
			assert_eq(files[sysconf.CRONTAB], "# mine\n", "only the operator's line remains")
			assert_contains(cmds[#cmds], "cron restart", "crond told")
			assert_contains(out, "cron jobs removed", "logged")
			-- Nothing managed, nothing pushed: no-op, no write.
			local n = #cmds
			assert_false(sysconf.apply_cron({enabled = false, jobs = {}}), "no-op")
			assert_eq(#cmds, n, "quiet")
		end
	},
	{
		name = "sysconf: apply runs all three parts, each in its own pcall, and skips absent ones",
		fn = function()
			local db = system_db("UTC", nil, nil)
			local commits, cmds, files = fresh(db)
			local r
			with_stderr(function() r = sysconf.apply(sysconf.parse(CAPTURE)) end)
			assert_true(r.timezone, "timezone changed")
			assert_true(r.ntp, "ntp changed")
			assert_true(r.cron, "cron written")
			assert_eq(#commits, 2, "system committed twice (timezone, ntp)")
			-- A raising part does not stop the others.
			sysconf._uci = {cursor = function() error("uci down") end}
			local out = with_stderr(function() r = sysconf.apply({timezone = "CET-1", cron = {enabled = false, jobs = {}}}) end)
			assert_false(r.timezone, "timezone part failed")
			assert_contains(out, "sysconf: timezone: ", "and was reported")
			assert_eq(#r, 0, "no crash")
			assert_eq(sysconf.apply(nil).timezone, nil, "nil parsed -> nothing")
		end
	},
}
