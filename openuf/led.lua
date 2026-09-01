--[[
	LED control for the controller-triggered "locate" identify action.

	Drives a Linux LED-class sysfs directory, configured as dev.conf.led in the
	modelmap. All operations are safe no-ops when that is unset (hardware whose
	LED name we don't know) or the sysfs path doesn't exist -- callers don't
	need to check availability themselves.

	Accepted dev.conf.led shapes, normalised by _resolve below:
	  "/sys/class/leds/tp-link:green:system"  full sysfs path
	  "tp-link:green:system"                  bare LED name
	  {sysfs = "tp-link:green:system", ...}   legacy modelmap table
	  nil                                     no LED (no-op)

	Anything else is treated as absent rather than raising: these functions are
	called from inform.lua's response dispatch, which is not wrapped in pcall,
	so throwing here would take down the inform daemon over a cosmetic setting.

	The LED named here need not be a dedicated status light. Some boards expose
	none -- a Xiaomi AX3000T has only its two mt76 radio LEDs -- so Locate
	snapshots whatever trigger the LED was driving and puts it back on stop
	rather than leaving it on a blanket "none". set_enabled deliberately does
	not: the controller's Manage > LED toggle means steady on/off, and on a
	board like that it does turn the radio LED into a plain indicator until the
	next Locate.
]]--

local M = {}

local LED_ROOT = "/sys/class/leds/"

-- Injectable: file writer, for sysfs LED control.
M._write_file = function(path, contents)
	local f = io.open(path, "w")
	if not f then return false end
	f:write(contents)
	f:close()
	return true
end

-- Injectable: file reader, for reading back an LED's current trigger.
M._read_file = function(path)
	local f = io.open(path, "r")
	if not f then return nil end
	local s = f:read("*a")
	f:close()
	return s
end

-- The trigger each LED was driving before locate_start took it over, keyed by
-- sysfs path. In-memory only: a Locate that outlives the daemon leaves the LED
-- blinking, which is the same thing a Locate that outlives the daemon did
-- before, and far better than persisting a snapshot that may be stale.
M._saved_trigger = {}

-- The active trigger from a sysfs `trigger` file, which lists every available
-- trigger and brackets the current one:
--   "none timer heartbeat netdev [phy0tpt] phy1tpt"
local function active_trigger(path)
	local s = M._read_file(path .. "/trigger")
	return type(s) == "string" and s:match("%[(%S-)%]") or nil
end

-- Normalise dev.conf.led into a sysfs directory path, or nil if unusable.
local function _resolve(led)
	if type(led) == "table" then led = led.sysfs end
	if type(led) ~= "string" or led == "" then return nil end
	-- A bare LED name (no path separator) is relative to /sys/class/leds.
	if not led:find("/", 1, true) then return LED_ROOT .. led end
	return led
end

-- Start the "locate" identify blink pattern (fast timer blink), remembering
-- whatever trigger the LED was already driving so locate_stop can put it back.
function M.locate_start(led)
	local led_path = _resolve(led)
	if not led_path then return false end
	M._saved_trigger[led_path] = active_trigger(led_path)
	M._write_file(led_path .. "/trigger", "timer")
	M._write_file(led_path .. "/delay_on", "250")
	M._write_file(led_path .. "/delay_off", "250")
	return true
end

-- Stop the "locate" identify blink pattern, restoring the trigger the LED was
-- driving when Locate started -- not a blanket "none".
--
-- The difference is not cosmetic on a board whose only driveable LED is a
-- radio's own: the AX3000T exposes nothing but mt76-phy0/mt76-phy1, whose
-- trigger is phy0tpt (the throughput blink). Writing "none" there ends Locate
-- by permanently killing the activity light -- a one-way change, made by a
-- transient identify action, that no later Locate undoes. Falls back to
-- "none" when the trigger could not be read, which is the old behaviour and
-- the only safe answer when the previous state is unknown.
function M.locate_stop(led)
	local led_path = _resolve(led)
	if not led_path then return false end
	M._write_file(led_path .. "/trigger", M._saved_trigger[led_path] or "none")
	M._saved_trigger[led_path] = nil
	return true
end

-- Set the steady-state LED on/off, per the controller's "Manage > LED"
-- toggle (mgmt_cfg's led_enabled key). Distinct from the locate blink above
-- -- this is the device's normal/idle LED state, not a transient identify
-- pattern.
function M.set_enabled(led, enabled)
	local led_path = _resolve(led)
	if not led_path then return false end
	M._write_file(led_path .. "/trigger", "none")
	M._write_file(led_path .. "/brightness", enabled and "1" or "0")
	return true
end

return M
