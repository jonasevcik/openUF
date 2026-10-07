-- Tests for openuf/usteer.lua (Band Steering via the usteer daemon).
-- Run from project root: lua tests/run_tests.lua
--
-- Uses the same in-memory mock UCI cursor shape as test_ucihelper.lua
-- (cursor:set/get/commit).

local usteer = dofile("openuf/usteer.lua")

local function new_mock_uci()
	local db = {}  -- db[config][section] = { [".name"]=.., [".type"]=.., key=val, ... }

	local cursor = {}

	function cursor:set(config, section, a, b)
		db[config] = db[config] or {}
		if not db[config][section] then
			db[config][section] = {[".name"] = section}
		end
		if b == nil then
			db[config][section][".type"] = a
		else
			db[config][section][a] = b
		end
	end

	function cursor:get(config, section, option)
		local s = db[config] and db[config][section]
		return s and s[option]
	end

	function cursor:delete(config, section, option)
		local s = db[config] and db[config][section]
		if s then s[option] = nil end
	end

	-- Recorded, not applied -- the counter lets tests catch a dropped commit.
	local commits = {}
	function cursor:commit(config)
		commits[config] = (commits[config] or 0) + 1
	end

	return {mock = {cursor = function() return cursor end}, db = db, commits = commits}
end

-- Fresh mock UCI + captured commands for each test.
local function with_usteer(fn)
	local m = new_mock_uci()
	local cmds = {}
	local orig_uci, orig_run = usteer._uci, usteer._run_cmd
	usteer._uci = m.mock
	usteer._run_cmd = function(cmd) cmds[#cmds + 1] = cmd; return true end
	local ok, err = pcall(fn, m.db, cmds, m.commits)
	usteer._uci, usteer._run_cmd = orig_uci, orig_run
	if not ok then error(err, 2) end
end

local function cmds_contain(cmds, substr)
	for _, c in ipairs(cmds) do
		if c:find(substr, 1, true) then return true end
	end
	return false
end

return {
	{
		name = "usteer: set_enabled(false) writes interval 0 and stops/disables the daemon",
		fn = function()
			with_usteer(function(db, cmds)
				local ok = usteer.set_enabled(false, nil)
				assert_true(ok, "set_enabled returns true")
				local s = db.usteer["local"]
				assert_eq(s.band_steering_interval, "0", "band steering off")
				assert_eq(s.network, "lan", "defaults network to lan without cfg")
				assert_true(cmds_contain(cmds, "usteer stop"), "stops the daemon")
				assert_true(cmds_contain(cmds, "usteer disable"), "disables the daemon")
			end)
		end
	},
	{
		name = "usteer: set_enabled(true) runs the daemon at its default steering interval",
		fn = function()
			with_usteer(function(db, cmds)
				local ok = usteer.set_enabled(true, nil)
				assert_true(ok, "set_enabled returns true")
				local s = db.usteer["local"]
				-- Unset, not a number of our own: usteer's default interval
				-- is the one that steered a real client (band_steering.c;
				-- 0 is the only value that disables it).
				assert_nil(s.band_steering_interval, "daemon default interval")
				assert_nil(s.band_steering_threshold, "inert threshold not written")
				assert_true(cmds_contain(cmds, "usteer enable"), "enables the daemon")
				assert_true(cmds_contain(cmds, "usteer restart"), "restarts the daemon")
			end)
		end
	},
	{
		name = "usteer: a repeated set_enabled is a no-op (no restart churn)",
		fn = function()
			-- set_enabled runs on every WiFi setparam; before the guard each
			-- steady-state inform restarted the daemon, dropping its learned
			-- station table.
			with_usteer(function(db, cmds, commits)
				assert_true(usteer.set_enabled(true, nil), "first call writes")
				local after_first = #cmds
				assert_eq(commits.usteer, 1, "first call commits")
				assert_true(usteer.set_enabled(true, nil), "second call still reports success")
				assert_eq(#cmds, after_first, "no second enable/restart issued")
				assert_eq(commits.usteer, 1, "steady state issues no further commits")

				usteer.set_enabled(false, nil)
				local after_disable = #cmds
				assert_true(after_disable > after_first, "transition to disabled acts")
				usteer.set_enabled(false, nil)
				assert_eq(#cmds, after_disable, "repeated disable issues no further commands")
			end)
		end
	},
	{
		name = "usteer: Roaming Assistant alone runs the daemon with band steering off",
		fn = function()
			with_usteer(function(db, cmds)
				usteer.set_enabled(false, nil, true)
				local s = db.usteer["local"]
				-- The daemon default steers, so running usteer for Roaming
				-- Assistant without this would band-steer too.
				assert_eq(s.band_steering_interval, "0", "no band steering")
				assert_eq(s.openuf_active, "1", "stamped as running")
				assert_true(cmds_contain(cmds, "usteer restart"), "daemon started")
				assert_false(cmds_contain(cmds, "usteer stop"), "not stopped")
				-- usteer's own device-wide roam trigger stays off: the decision
				-- is roamassist.lua's, per WLAN.
				assert_nil(s.roam_trigger_snr, "no roam_trigger_snr")
				assert_nil(s.signal_diff_threshold, "no signal_diff_threshold")
			end)
		end
	},
	{
		name = "usteer: turning Roaming Assistant off (band steering off) stops the daemon",
		fn = function()
			-- The case an options-only guard would swallow: the interval is
			-- "0" before and after, only the running state moves.
			with_usteer(function(db, cmds)
				usteer.set_enabled(false, nil, true)
				local n = #cmds
				usteer.set_enabled(false, nil, false)
				assert_true(#cmds > n, "acted on the transition")
				assert_true(cmds_contain(cmds, "usteer stop"), "stopped")
				assert_eq(db.usteer["local"].openuf_active, "0", "stamped as stopped")
				local m = #cmds
				usteer.set_enabled(false, nil, false)
				assert_eq(#cmds, m, "steady off is a no-op")
			end)
		end
	},
	{
		name = "usteer: a device configured by an older openUF is rewritten once",
		fn = function()
			with_usteer(function(db, cmds, commits)
				local cursor = usteer._uci.cursor()
				cursor:set("usteer", "local", "usteer")
				cursor:set("usteer", "local", "network", "lan")
				cursor:set("usteer", "local", "band_steering_threshold", "5")
				cursor:set("usteer", "local", "openuf_active", "1")
				usteer.set_enabled(true, nil)
				assert_eq(commits.usteer, 1, "one migration write")
				assert_nil(db.usteer["local"].band_steering_threshold,
					"the threshold the old version wrote is removed")
				usteer.set_enabled(true, nil)
				assert_eq(commits.usteer, 1, "then steady")
			end)
		end
	},
	{
		name = "usteer: set_enabled uses cfg.net.lan_name when present",
		fn = function()
			with_usteer(function(db, cmds)
				usteer.set_enabled(true, {net = {lan_name = "br-lan"}})
				assert_eq(db.usteer["local"].network, "br-lan", "network taken from cfg")
			end)
		end
	},
	{
		name = "usteer: reconcile_filter drops the sync on every VAP, first fragments and the rest",
		fn = function()
			local cmds, orig = {}, usteer._exec
			usteer._exec = function(c) cmds[#cmds + 1] = c; return 0 end
			local n = usteer.reconcile_filter({"phy0-ap0", "phy1-ap0", "bad name;rm"})
			usteer._exec = orig
			assert_eq(n, 3, "three rules installed")
			assert_true(cmds[1]:find("delete table bridge openuf_usteer", 1, true) ~= nil, "rebuilt from scratch")
			assert_true(cmds_contain(cmds, "hook postrouting"), "postrouting sees local and forwarded frames")
			assert_true(cmds_contain(cmds, 'oifname { "phy0-ap0", "phy1-ap0" } ip daddr 255.255.255.255 udp dport 16720 drop'),
				"first fragment / whole datagram, on both VAPs")
			assert_true(cmds_contain(cmds, "ip daddr 255.255.255.255 ip protocol udp ip frag-off & 0x1fff != 0 drop"),
				"the later fragments, which carry no UDP header")
			assert_true(cmds_contain(cmds, "ip6 daddr ff02::4150 drop"), "usteer's ipv6 mode")
			assert_false(cmds_contain(cmds, "bad name"), "an odd ifname never reaches the shell")
			assert_false(cmds_contain(cmds, "udp dport 68"), "nothing else is touched")
		end
	},
	{
		name = "usteer: reconcile_filter with no VAPs only removes the table; a rejected rule is not counted",
		fn = function()
			local cmds, orig, origerr = {}, usteer._exec, io.stderr
			io.stderr = {write = function() end}
			usteer._exec = function(c) cmds[#cmds + 1] = c; return 0 end
			local none = usteer.reconcile_filter({})
			local ncmds = #cmds
			usteer._exec = function(c) return c:find("add rule", 1, true) and 1 or 0 end
			local rejected = usteer.reconcile_filter({"phy0-ap0"})
			usteer._exec, io.stderr = orig, origerr
			assert_eq(none, 0, "nothing installed")
			assert_eq(ncmds, 1, "just the delete")
			assert_eq(rejected, 0, "Lua 5.1 exit status 1 is a failure, not success")
		end
	},
	{
		name = "usteer: filter_wanted follows openuf_active",
		fn = function()
			with_usteer(function(db)
				assert_false(usteer.filter_wanted(), "never configured")
				usteer.set_enabled(false, nil, true)
				assert_true(usteer.filter_wanted(), "running for Roaming Assistant")
				usteer.set_enabled(false, nil, false)
				assert_false(usteer.filter_wanted(), "stopped")
			end)
		end
	},
}
