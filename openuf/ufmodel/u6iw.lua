--[[
	U6-InWall device identity.

	fw.ver may need adjustment to match the firmware versions accepted by your
	controller version. Identify a compatible range by checking the controller's
	device firmware list or by capturing announce packets from a real U6-InWall.
]]--

local uap = {}

uap = {
	platform		= "U6IW",
	model			= "U6IW",
	fw				= {
		pre			= "U6IW.",
		-- Matches the real U6IW release firmware (v6.8.2+15592) as of
		-- 2026-07 -- confirmed directly against a live controller's own
		-- autoupdate-check log ("firmware[U6IW] new version (6.8.2.15592)
		-- is available") during Stage 2c validation. An older ver here
		-- makes the controller show a spurious "device has an update"
		-- offer for a fake AP with no real firmware to install.
		ver			= "6.8.2.15592",	-- format M.m.p.build — tune for your controller
		buildtime	= "260211.2010",	-- format YYMMDD.HHMM
		factoryver	= "6.5.28"
	},
	bootver			= "",
	required_version = "6.0.0",			-- minimum controller version
}

return uap
