-- Tests for openuf/inflate.lua (pure-Lua DEFLATE / zlib).
-- Run from project root: lua tests/run_tests.lua
--
-- WHY THIS FILE EXISTS
--
-- This is not a fallback path. inform.lua prefers a native `zlib` binding and
-- falls back to this module -- but OpenWrt 25.12 ships no Lua zlib binding, so
-- on every real target the fallback IS the path: every FLAG_COMPRESSED
-- response from the controller is decompressed by the code under test here. A
-- bug in it fails the inform outright, and until now 225 lines of hand-written
-- bitstream reader, Huffman table builder and dynamic-table decoder had no
-- test of any kind.
--
-- The three DEFLATE block types are all exercised, because they share almost
-- no code: stored (btype 0) bypasses Huffman entirely, fixed (btype 1) uses
-- the RFC's built-in tables, and dynamic (btype 2) has to decode the
-- code-length alphabet first -- by far the most intricate part of the module.
--
-- Fixtures are real zlib output, kept as hex so they stay reviewable in a
-- diff. Regenerate with:
--   python3 -c 'import zlib; print(zlib.compress(b"...", 9).hex())'
-- The block type of a stream is bits 1-2 of its first DEFLATE byte, i.e.
-- (byte(data, 3) >> 1) % 4 counting the two-byte zlib header.

local inflate = dofile("openuf/inflate.lua")

-- Hex string -> binary. Fixtures are hex so a byte-level diff is readable.
local function unhex(h)
	return (h:gsub("%x%x", function(cc)
		return string.char(tonumber(cc, 16))
	end))
end

-- Stored / uncompressed block (btype 0), from zlib.compress(data, 0).
local STORED_Z = ""
		.. "7801011800e7ff6f70656e55466f70656e55466f70656e55466f70656e554675"
		.. "4c0935"
local STORED_PLAIN = "openUFopenUFopenUFopenUF"

-- Fixed-Huffman block (btype 1): short, highly repetitive input.
local FIXED_Z = ""
		.. "78da4b4cc40700b04f0b5f"
local FIXED_PLAIN = string.rep("a", 30)

-- Dynamic-Huffman block (btype 2): a controller setparam response, the
-- realistic shape -- this is what actually arrives on the wire.
local DYN_Z = ""
		.. "78da5dd4d14ac3401484e157915c6be99949938de09b08a1d4ad044c0cd95429"
		.. "e2bb6bbd9099dc2dfc57fb71cef9aafaf53ae7eaf1ae2a799d8fcb71acee7fdf"
		.. "d7b2e6b13f9d5f6fe57358f25b2e6517bb528697a7f7394f97f3433c4fff0556"
		.. "20855628a5b6524b3958394869ac34525a2bad94642549e9ac745262ef5fdd6b"
		.. "db30a8433844a8443845a8453846a8463847a8473848a8483849a849384aa84a"
		.. "384ba80bdc05ea027781cdc76640d405ee027581bb405de02e5017b80bd405ee"
		.. "027581bb405de02e5017ba0bd585ee4275a1bbd03667b33aea4277a1bad05da8"
		.. "2e7417aa0bdd85ea4277a1bad05dd8fd5d90bc7ce4a55f8731f7c3d45fd6d3ed"
		.. "92449b98ea480d13507dff0020879b93"

local function dyn_plain()
	local parts = {}
	for i = 1, 39 do
		parts[#parts + 1] = string.format("wireless.%d.ssid=openuf-%d", i, i)
	end
	return '{"_type": "setparam", "system_cfg": "' ..
		table.concat(parts, "\\n") ..
		'", "server_time_in_utc": "1783841863822"}'
end

-- The block type actually encoded in a zlib stream, so a regenerated fixture
-- that silently changes shape fails loudly instead of quietly testing the
-- same path twice.
local function btype(z)
	return math.floor(z:byte(3) / 2) % 4
end

return {
	{
		name = "inflate: a stored (uncompressed) block round-trips",
		fn = function()
			local z = unhex(STORED_Z)
			assert_eq(btype(z), 0, "fixture really is a stored block")
			assert_eq(inflate.zlib_decompress(z), STORED_PLAIN, "stored block decodes")
		end
	},
	{
		name = "inflate: a fixed-Huffman block round-trips",
		fn = function()
			local z = unhex(FIXED_Z)
			assert_eq(btype(z), 1, "fixture really is a fixed-Huffman block")
			assert_eq(inflate.zlib_decompress(z), FIXED_PLAIN, "fixed-Huffman block decodes")
		end
	},
	{
		name = "inflate: a dynamic-Huffman controller response round-trips",
		fn = function()
			local z = unhex(DYN_Z)
			assert_eq(btype(z), 2, "fixture really is a dynamic-Huffman block")
			local out = inflate.zlib_decompress(z)
			assert_eq(#out, #dyn_plain(), "decoded length matches")
			assert_eq(out, dyn_plain(), "dynamic-Huffman block decodes byte for byte")
		end
	},
	{
		name = "inflate: the decoded payload survives a cjson round-trip",
		fn = function()
			-- The real consumer is parse_packet -> cjson.decode. A decoder that
			-- is off by one byte usually still returns a string; it stops being
			-- JSON.
			local cjson = require("cjson")
			local obj = cjson.decode(inflate.zlib_decompress(unhex(DYN_Z)))
			assert_eq(obj._type, "setparam", "the response type survives")
			assert_true(obj.system_cfg:find("wireless.39.ssid=openuf-39", 1, true) ~= nil,
				"the last system_cfg line is intact, so nothing was truncated")
		end
	},
	{
		name = "inflate: inflate() takes a raw DEFLATE stream without the zlib wrapper",
		fn = function()
			-- zlib_decompress is a 2-byte header and a 4-byte Adler-32 trailer
			-- around exactly this.
			local z = unhex(DYN_Z)
			local raw = z:sub(3, #z - 4)
			assert_eq(inflate.inflate(raw), dyn_plain(), "raw DEFLATE decodes identically")
		end
	},
	{
		name = "inflate: a stream that is not zlib-DEFLATE is rejected, not misread",
		fn = function()
			-- CM (low nibble of byte 1) must be 8. Anything else is some other
			-- format, and guessing at it would hand cjson garbage.
			local ok, err = pcall(inflate.zlib_decompress, "\x79\x01abcdefgh")
			assert_false(ok, "a non-DEFLATE stream raises")
			assert_true(tostring(err):find("CM~=8", 1, true) ~= nil,
				"and says which check failed")

			assert_false(pcall(inflate.zlib_decompress, "x"), "a 1-byte stream raises")
		end
	},
	{
		name = "inflate: a truncated stream raises instead of returning a short payload",
		fn = function()
			-- A response cut off in transit must not decode to a prefix that
			-- parse_packet then hands to cjson: a partial system_cfg would be
			-- applied as if it were the whole config.
			local z = unhex(DYN_Z)
			local ok = pcall(inflate.zlib_decompress, z:sub(1, math.floor(#z / 2)))
			assert_false(ok, "half a stream does not decode quietly")
		end
	},
	{
		name = "inflate: an all-zero stream terminates instead of looping forever",
		fn = function()
			-- The exact shape that used to hang the daemon. The bitstream read
			-- `byte(data, pos) or 0`, so past the end it supplied zero bits
			-- indefinitely: bfinal=0, btype=0 (stored), LEN=0 -- a zero-length
			-- block that emits nothing and never sets bfinal. M.inflate's
			-- `repeat ... until bfinal == 1` spun on that in a tight loop with
			-- no error and no heartbeat, and procd cannot respawn a process
			-- that never exits. Any truncated or corrupted FLAG_COMPRESSED
			-- response from the controller reached this.
			local ok = pcall(inflate.inflate, string.rep("\0", 8))
			assert_false(ok, "raises rather than spinning on zero-length blocks")
		end
	},
	{
		name = "inflate: reserved block type 3 is rejected",
		fn = function()
			-- bfinal=1, btype=3 -> 0x07. RFC 1951 reserves it; treating it as
			-- anything else would desynchronise the bitstream.
			local ok, err = pcall(inflate.inflate, "\x07")
			assert_false(ok, "reserved block type raises")
			assert_true(tostring(err):find("reserved block type 3", 1, true) ~= nil,
				"and names the reason")
		end
	},
}
