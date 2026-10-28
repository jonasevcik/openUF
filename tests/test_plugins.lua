-- Tests for openuf/plugins.lua (opt-in third-party edits to per-VAP UCI
-- options) and its use in ucihelper.apply_config.
-- Run from project root: lua tests/run_tests.lua

local plugins   = dofile("openuf/plugins.lua")
local ucihelper = dofile("openuf/ucihelper.lua")

local DELETE = setmetatable({}, {__tostring = function() return "<delete>" end})
local ENV = {DELETE = DELETE, bssid = function() return "00:00:5e:00:53:2b" end,
	cursor = function() return {} end}

-- Run fn with plugins' seams stubbed: `files` maps plugin name -> Lua source,
-- log lines are collected, and the load cache starts empty.
local function with_plugins(files, fn)
	local orig_read, orig_log = plugins._read_file, plugins._log
	local logged = {}
	plugins._read_file = function(path)
		return files[path:match("^" .. plugins.DIR:gsub("%p", "%%%0") .. "/(.+)%.lua$")]
	end
	plugins._log = function(msg) logged[#logged + 1] = msg end
	plugins._reset()
	local ok, err = pcall(fn, logged)
	plugins._read_file, plugins._log = orig_read, orig_log
	plugins._reset()
	if not ok then error(err, 0) end
end

local function has_log(logged, text)
	for _, l in ipairs(logged) do
		if l:find(text, 1, true) then return true end
	end
	return false
end

local function cfg_of(...) return {config = {plugins = {...}}} end

local function plugin_src(body)
	return "return {name = 'p', api = 1, vap_options = function(extra, vap, ctx)\n"
		.. body .. "\nend}"
end

local VAP = {ssid = "corp", radio = "radio0", x_passphrase = "hunter22",
	iapp_key = "00112233445566778899aabbccddeeff"}

return {
	{
		name = "plugins: nothing is loaded unless conf.lua names it",
		fn = function()
			with_plugins({p = plugin_src("extra.touched = '1'")}, function(logged)
				local extra = {a = "1"}
				plugins.vap_options(extra, VAP, nil, ENV)
				plugins.vap_options(extra, VAP, {config = {}}, ENV)
				plugins.vap_options(extra, VAP, cfg_of(), ENV)
				assert_nil(extra.touched, "a file in the directory is not enough")
				assert_eq(#logged, 0, "and nothing is logged")
			end)
		end
	},
	{
		name = "plugins: a listed plugin edits extra, sees the vap and ctx, never the passphrase",
		fn = function()
			local src = plugin_src([[
				extra.mobility_domain = 'abcd'
				extra.r0kh = {'ff:ff:ff:ff:ff:ff,*,' .. vap.iapp_key}
				extra.reassociation_deadline = ctx.DELETE
				extra.nasid = (ctx.bssid(vap.radio, vap.ssid):gsub(':', ''))
				extra.leak = tostring(vap.x_passphrase)
				ctx.log('hello')]])
			with_plugins({p = src}, function(logged)
				local extra = {mobility_domain = "ffff", reassociation_deadline = "3000"}
				plugins.vap_options(extra, VAP, cfg_of("p"), ENV)
				assert_eq(extra.mobility_domain, "abcd", "may override a built-in option")
				assert_eq(extra.r0kh[1], "ff:ff:ff:ff:ff:ff,*," .. VAP.iapp_key, "list option")
				assert_true(extra.reassociation_deadline == DELETE, "the DELETE sentinel survives")
				assert_eq(extra.nasid, "00005e00532b", "ctx.bssid")
				assert_eq(extra.leak, "nil", "the passphrase is not handed over")
				assert_true(has_log(logged, "p: hello"), "ctx.log carries the plugin name")
				assert_eq(VAP.x_passphrase, "hunter22", "and the caller's vap is untouched")
				-- openUF's own DELETE entries (vendor_elements, macfilter, ...) pass
				-- through a plugin that ignores them, still the same sentinel.
				local e2 = {vendor_elements = DELETE}
				plugins.vap_options(e2, VAP, cfg_of("p"), ENV)
				assert_true(e2.vendor_elements == DELETE, "a built-in DELETE keeps its identity")
			end)
		end
	},
	{
		name = "plugins: a plugin that is missing, broken, or on another api is skipped, the rest still run",
		fn = function()
			with_plugins({
				bad_syntax = "return {",
				wrong_api  = "return {api = 99, vap_options = function() end}",
				no_hook    = "return {api = 1}",
				not_table  = "return 5",
				good       = plugin_src("extra.ok = '1'"),
			}, function(logged)
				local extra = {}
				plugins.vap_options(extra, VAP,
					cfg_of("missing", "bad_syntax", "wrong_api", "no_hook", "not_table",
						"../etc/passwd", "good"), ENV)
				assert_eq(extra.ok, "1", "the good plugin ran")
				assert_true(has_log(logged, "missing: not loaded"), "missing")
				assert_true(has_log(logged, "bad_syntax: not loaded"), "syntax error")
				assert_true(has_log(logged, "api 99"), "api mismatch names both versions")
				assert_true(has_log(logged, "no vap_options"), "no hook")
				assert_true(has_log(logged, "did not return a table"), "wrong type")
				assert_true(has_log(logged, "invalid plugin name"), "no path traversal")
			end)
		end
	},
	{
		name = "plugins: a hook that raises changes nothing and the push goes on",
		fn = function()
			with_plugins({
				boom = plugin_src("extra.half = '1'; error('kaboom')"),
				good = plugin_src("extra.ok = '1'"),
			}, function(logged)
				local extra = {keep = "1"}
				plugins.vap_options(extra, VAP, cfg_of("boom", "good"), ENV)
				assert_nil(extra.half, "the partial edit is discarded")
				assert_eq(extra.keep, "1", "existing options stay")
				assert_eq(extra.ok, "1", "the next plugin still runs")
				assert_true(has_log(logged, "kaboom"), "the error is logged")
				assert_true(has_log(logged, "corp"), "with the WLAN it concerned")
			end)
		end
	},
	{
		name = "plugins: an invalid edit is refused whole (names, reserved options, value types)",
		fn = function()
			local cases = {
				{"extra['bad-name'] = '1'", "bad-name"},
				{"extra['a b'] = '1'", "a b"},
				{"extra.ssid = 'evil'", "reserved"},
				{"extra.key = 'evil'", "reserved"},
				{"extra.network = 'wan'", "reserved"},
				{"extra.openuf_ratelimit_down = '1'", "reserved"},
				{"extra.fn = function() end", "function"},
				{"extra.lst = {{}}", "list element"},
			}
			for _, c in ipairs(cases) do
				with_plugins({p = plugin_src("extra.fine = '1'; " .. c[1])}, function(logged)
					local extra = {ssid_stays = "1"}
					plugins.vap_options(extra, VAP, cfg_of("p"), ENV)
					assert_nil(extra.fine, c[2] .. ": the valid part is not applied either")
					assert_true(has_log(logged, c[2]), c[2] .. ": says why")
				end)
			end
			-- An option openUF already set may be left as it is: only a
			-- change to a reserved name is refused.
			with_plugins({p = plugin_src("extra.fine = '1'")}, function()
				local extra = {openuf_bcfilt = "1", ssid = "x", lst = {"a", "b"}}
				plugins.vap_options(extra, VAP, cfg_of("p"), ENV)
				assert_eq(extra.fine, "1", "untouched reserved and list options do not trip the check")
			end)
		end
	},
	{
		name = "plugins: a name listed twice runs once; a non-list config is ignored with a log line",
		fn = function()
			with_plugins({p = plugin_src("extra.n = tostring(tonumber(extra.n or 0) + 1)")},
				function(logged)
					local extra = {}
					plugins.vap_options(extra, VAP, cfg_of("p", "p"), ENV)
					assert_eq(extra.n, "1", "ran once")
					plugins.vap_options(extra, VAP, {config = {plugins = "p"}}, ENV)
					assert_true(has_log(logged, "must be a list"), "string config refused")
				end)
		end
	},
	{
		name = "plugins: apply_config writes a plugin's options, and nothing changes with plugins off",
		fn = function()
			local function run(cfg)
				local db
				-- A minimal in-memory cursor (set/get/delete/foreach/commit),
				-- strict about section names like the real libuci is silent.
				db = {}
				local order = {}
				local c = {}
				function c:set(config, section, a, b)
					assert(tostring(section):match("^[%w_]+$"), "invalid section " .. tostring(section))
					db[config] = db[config] or {}
					if not db[config][section] then
						db[config][section] = {[".name"] = section}
						order[config] = order[config] or {}
						order[config][#order[config] + 1] = section
					end
					if b == nil then db[config][section][".type"] = a
					elseif type(b) == "table" then
						local l = {}
						for i, v in ipairs(b) do l[i] = tostring(v) end
						db[config][section][a] = l
					else db[config][section][a] = b end
				end
				function c:foreach(config, stype, fn)
					for _, n in ipairs(order[config] or {}) do
						local s = db[config][n]
						if s and s[".type"] == stype then fn(s) end
					end
				end
				function c:delete(config, section, option)
					if option ~= nil then
						if db[config] and db[config][section] then db[config][section][option] = nil end
						return
					end
					if db[config] then db[config][section] = nil end
					for i, n in ipairs(order[config] or {}) do
						if n == section then table.remove(order[config], i); break end
					end
				end
				function c:get(config, section, option)
					local s = db[config] and db[config][section]
					return s and s[option]
				end
				function c:commit() end
				local orig = {ucihelper._uci, ucihelper._popen, ucihelper._read_file,
					ucihelper._run_cmd, ucihelper._plugins, ucihelper._bcfilter}
				ucihelper._uci = {cursor = function() return c end}
				ucihelper._popen = function() return "" end
				ucihelper._read_file = function() return nil end
				ucihelper._run_cmd = function() return true end
				ucihelper._plugins = plugins
				-- The real bcfilter would rebuild an nft table: never from a test.
				ucihelper._bcfilter = {reconcile = function() end}
				c:set("wireless", "radio0", "wifi-device")
				local real = io.stderr
				io.stderr = {write = function() end}
				local ok, err = pcall(ucihelper.apply_config, {radio_table = {}, vap_table = {
					{ssid = "corp", radio = "radio0", security = "wpa2",
					 x_passphrase = "hunter22", fast_roaming_enabled = true,
					 iapp_key = VAP.iapp_key},
				}}, cfg)
				io.stderr = real
				ucihelper._uci, ucihelper._popen, ucihelper._read_file,
					ucihelper._run_cmd, ucihelper._plugins, ucihelper._bcfilter =
					orig[1], orig[2], orig[3], orig[4], orig[5], orig[6]
				if not ok then error(err, 0) end
				return db.wireless.openuf_radio0_corp, db
			end

			local base = run(nil)
			local off  = run({config = {plugins = {}}})
			for k, v in pairs(base) do
				if type(v) == "table" then
					assert_eq(table.concat(off[k], ","), table.concat(v, ","), "plugins={}: " .. k)
				else
					assert_eq(off[k], v, "plugins={}: " .. k)
				end
			end
			for k in pairs(off) do assert_true(base[k] ~= nil, "plugins={}: no extra option " .. k) end

			with_plugins({p = plugin_src([[
				extra.mobility_domain = 'abcd'
				extra.ft_psk_generate_local = '0'
				extra.hostapd_bss_options = {'ft_iface=vft0'}
				extra.reassociation_deadline = ctx.DELETE]])}, function()
				local s = run({config = {plugins = {"p"}}})
				assert_eq(s.mobility_domain, "abcd", "overrides openUF's value")
				assert_eq(s.ft_psk_generate_local, "0", "adds an option")
				assert_eq(s.hostapd_bss_options[1], "ft_iface=vft0", "list option reaches UCI")
				assert_nil(s.reassociation_deadline, "DELETE removes openUF's 3000")
				assert_eq(s.ssid, "corp", "identity untouched")
				-- And dropping the plugin from the list drops its options on
				-- the next push: sections are rebuilt from scratch.
				local gone = run({config = {plugins = {}}})
				assert_nil(gone.ft_psk_generate_local, "unlisted -> its option is gone")
				assert_eq(gone.mobility_domain, base.mobility_domain, "and openUF's value is back")
			end)
		end
	},
	{
		name = "plugins: ctx.util hands a plugin the shared helpers, and only those",
		fn = function()
			with_plugins({p = plugin_src([[
				local u = ctx.util
				extra.mac = u.is_mac('00:00:5e:00:53:01') and 'y' or 'n'
				extra.badif = u.valid_ifname('this-name-is-way-too-long') and 'y' or 'n'
				extra.bit = tostring(u.bit.band(6, 3))
				extra.rf = type(u.read_file)
				local n = 0
				for _ in pairs(u) do n = n + 1 end
				extra.n = tostring(n)]])}, function()
				local extra = {}
				plugins.vap_options(extra, VAP, cfg_of("p"), ENV)
				assert_eq(extra.mac, "y", "is_mac")
				assert_eq(extra.badif, "n", "valid_ifname")
				assert_eq(extra.bit, "2", "bit shim")
				assert_eq(extra.rf, "function", "read_file")
				assert_eq(extra.n, "4", "nothing else leaks")
			end)
		end
	},
	{
		name = "plugins: /etc/openuf/plugins.enabled adds names beside conf.lua's, deduped",
		fn = function()
			local orig = plugins._read_file
			with_plugins({a = plugin_src("extra.a = '1'"), b = plugin_src("extra.b = '1'")}, function()
				local files_read = plugins._read_file
				plugins._read_file = function(path)
					if path == plugins.LIST then
						return "# installed by x\nb  # trailing\n\n  a\r\n../evil\n"
					end
					return files_read(path)
				end
				local list = plugins.enabled(cfg_of("a"))
				assert_eq(#list, 2, "a once (conf.lua), b from the file; ../evil refused")
				assert_eq(list[1].name, "a", "conf.lua first")
				assert_eq(list[2].name, "b", "then the file")
				-- The file alone is enough, with no config.plugins at all.
				assert_eq(#plugins.enabled({config = {}}), 2, "file without conf.lua key")
				local extra = {}
				plugins.vap_options(extra, VAP, {config = {}}, ENV)
				assert_eq(extra.b, "1", "and the plugin runs")
			end)
			plugins._read_file = orig
		end
	},
	{
		name = "plugins: the enabled list is read once per push, not once per VAP",
		fn = function()
			local orig = plugins._read_file
			local ok, err = pcall(function()
				local reads, listing = 0, ""
				plugins._read_file = function(path)
					if path == plugins.LIST then
						reads = reads + 1
						return listing
					end
					return nil
				end
				plugins._reset()
				plugins.end_pass()

				-- The zero-plugin install, which is every install until
				-- someone drops a file in: eight WLANs on a push.
				local cfg = {config = {}}
				for _ = 1, 8 do plugins.vap_options({}, VAP, cfg, ENV) end
				assert_eq(reads, 8, "outside a pass every call re-reads the list")

				reads = 0
				plugins.begin_pass()
				for _ = 1, 8 do plugins.vap_options({}, VAP, cfg, ENV) end
				assert_eq(reads, 1, "inside one, eight VAPs cost one file open")

				-- The pass is dropped on entry, not only on exit: a push that
				-- raised inside the VAP loop left the pass open, and the next
				-- one must not be served that stale list. Same cfg table, so
				-- only the re-open can explain the re-read. (No end_pass()
				-- before it on purpose -- that is the leaked-pass case.)
				reads, listing = 0, "\n# nothing enabled\n"
				plugins.begin_pass()
				plugins.vap_options({}, VAP, cfg, ENV)
				assert_eq(reads, 1, "a re-opened pass re-reads")

				-- A different config inside the same pass is a different
				-- question, so it is not served the first answer.
				reads = 0
				plugins.vap_options({}, VAP, {config = {}}, ENV)
				assert_eq(reads, 1, "another cfg table is re-read")
				plugins.end_pass()
				assert_eq(plugins._pass_list, nil, "and end_pass drops the answer")
			end)
			plugins._read_file = orig
			plugins.end_pass()
			plugins._reset()
			if not ok then error(err, 0) end
		end
	},
	{
		name = "plugins: fingerprint moves with the list and with a plugin's source",
		fn = function()
			with_plugins({a = plugin_src("extra.a = '1'")}, function()
				local none = plugins.fingerprint({config = {}})
				assert_eq(none, "", "nothing requested -> empty")
				local one = plugins.fingerprint(cfg_of("a"))
				assert_true(one ~= none, "adding a name changes it")
				assert_eq(plugins.fingerprint(cfg_of("a")), one, "stable")
				assert_true(plugins.fingerprint(cfg_of("a", "missing")) ~= one, "a missing file still counts")
			end)
			with_plugins({a = plugin_src("extra.a = '2'")}, function()
				with_plugins({a = plugin_src("extra.a = '1'")}, function() end)
			end)
			local fp1, fp2
			with_plugins({a = plugin_src("extra.a = '1'")}, function() fp1 = plugins.fingerprint(cfg_of("a")) end)
			with_plugins({a = plugin_src("extra.a = '2'")}, function() fp2 = plugins.fingerprint(cfg_of("a")) end)
			assert_true(fp1 ~= fp2, "editing the plugin changes it")
		end
	},
	{
		name = "inform: startup forgets cfgversion only when the plugin fingerprint moved",
		fn = function()
			OPENUF_TEST_MODE = true
			local inform = dofile("openuf/inform.lua")
			local saved = 0
			local orig_state, orig_plugins = inform._state, inform._plugins
			inform._state = setmetatable({save = function() saved = saved + 1 end}, {__index = orig_state})
			local fp = "a:1"
			inform._plugins = {fingerprint = function() return fp end}
			local function st(t) t.cfgversion = t.cfgversion or "v1"; return t end

			local s = st({adopted = true, plugins_fp = "a:1"})
			inform._reconcile_plugins(s, {})
			assert_eq(s.cfgversion, "v1", "unchanged -> kept")
			assert_eq(saved, 0, "and not rewritten")

			fp = "a:2"
			inform._reconcile_plugins(s, {})
			assert_eq(s.cfgversion, "", "changed -> controller must push again")
			assert_eq(s.plugins_fp, "a:2", "recorded")
			assert_eq(saved, 1, "saved")

			local fresh = st({adopted = false})
			inform._reconcile_plugins(fresh, {})
			assert_eq(fresh.cfgversion, "v1", "never adopted -> nothing stale")
			assert_eq(fresh.plugins_fp, "a:2", "but recorded")

			fp = ""
			local none = st({adopted = true})
			inform._reconcile_plugins(none, {})
			assert_eq(none.cfgversion, "v1", "no plugins ever -> untouched")
			inform._state, inform._plugins = orig_state, orig_plugins
		end
	},
}
