--[[
	Pure-Lua DEFLATE / zlib decompressor (RFC 1951 / RFC 1950).

	OpenWrt 25.12 ships no Lua zlib binding, but UniFi controllers zlib-compress
	inform responses whenever it shrinks the payload (e.g. full config pushes).
	Without a decompressor those responses cannot be parsed, which stalls
	adoption. This module supplies inflate so no external package is needed.

	Decompression only — openUF always sends its own informs uncompressed.

	Lua 5.1-safe: the bit reader uses plain arithmetic (no bitwise operators and
	no dependency on the "bit"/"bit32" module), so it runs identically on the
	OpenWrt Lua 5.1 runtime and on newer dev hosts.
]]--

local M = {}

local byte   = string.byte
local char   = string.char
local floor  = math.floor
local concat = table.concat

-- ─── LSB-first bit reader ────────────────────────────────────────────────────

local function bitstream(data)
	local pos    = 1   -- 1-based next byte
	local bitbuf = 0
	local bitcnt = 0
	local bs = {}

	function bs.getbit()
		if bitcnt == 0 then
			-- Running off the end is an ERROR, not a supply of zero bits.
			-- Faking zeroes here does not degrade gracefully: M.inflate's
			-- `repeat ... until bfinal == 1` reads bfinal=0, btype=0 (stored)
			-- and a length of 0 forever, so a truncated or corrupted response
			-- HUNG the inform loop in a tight zero-length-block loop -- no
			-- error, no heartbeat, no recovery, and procd cannot respawn a
			-- process that never exits. Raising instead lands in _tick's
			-- pcall around parse_packet, which costs one heartbeat and logs.
			bitbuf = byte(data, pos)
			if not bitbuf then error("inflate: truncated stream") end
			pos    = pos + 1
			bitcnt = 8
		end
		local b = bitbuf % 2
		bitbuf  = (bitbuf - b) / 2
		bitcnt  = bitcnt - 1
		return b
	end

	function bs.getbits(n)
		local v, mul = 0, 1
		for _ = 1, n do
			v   = v + bs.getbit() * mul
			mul = mul * 2
		end
		return v
	end

	function bs.align()  bitcnt = 0 end          -- discard to byte boundary
	function bs.getbyte()
		local b = byte(data, pos)
		if not b then error("inflate: truncated stream") end
		pos = pos + 1
		return b
	end

	return bs
end

-- ─── Canonical Huffman (puff-style count/symbol tables) ──────────────────────

local function build_huffman(lengths, n)
	local h = {count = {}, symbol = {}}
	for i = 0, 15 do h.count[i] = 0 end
	for i = 1, n do h.count[lengths[i]] = h.count[lengths[i]] + 1 end

	local offs = {[1] = 0}
	for len = 1, 15 do offs[len + 1] = offs[len] + h.count[len] end
	for i = 1, n do
		local l = lengths[i]
		if l ~= 0 then
			h.symbol[offs[l]] = i - 1   -- 0-based symbol
			offs[l] = offs[l] + 1
		end
	end
	return h
end

local function decode_sym(bs, h)
	local code, first, index = 0, 0, 0
	for len = 1, 15 do
		code = code + bs.getbit()
		local count = h.count[len]
		if code - first < count then
			return h.symbol[index + (code - first)]
		end
		index = index + count
		first = (first + count) * 2
		code  = code * 2
	end
	error("inflate: invalid Huffman code")
end

-- ─── RFC 1951 length/distance base + extra-bit tables ────────────────────────

local LEN_BASE = {
	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
	35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 }
local LEN_EXTRA = {
	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
	3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 }
local DIST_BASE = {
	1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
	257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
	8193, 12289, 16385, 24577 }
local DIST_EXTRA = {
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
	7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 }

-- Code-length-code ordering for dynamic Huffman headers
local CL_ORDER = {17, 18, 19, 1, 9, 8, 10, 7, 11, 6, 12, 5, 13, 4, 14, 3, 15, 2, 16}

-- Fixed Huffman tables (built once, lazily)
local _fixed_lit, _fixed_dist
local function fixed_tables()
	if _fixed_lit then return _fixed_lit, _fixed_dist end
	local ll = {}
	for i = 1, 144   do ll[i] = 8 end
	for i = 145, 256 do ll[i] = 9 end
	for i = 257, 280 do ll[i] = 7 end
	for i = 281, 288 do ll[i] = 8 end
	local dl = {}
	for i = 1, 30 do dl[i] = 5 end
	_fixed_lit  = build_huffman(ll, 288)
	_fixed_dist = build_huffman(dl, 30)
	return _fixed_lit, _fixed_dist
end

-- ─── Block inflation ─────────────────────────────────────────────────────────

local function inflate_block(bs, lithuff, disthuff, out)
	while true do
		local sym = decode_sym(bs, lithuff)
		if sym == 256 then
			return
		elseif sym < 256 then
			out[#out + 1] = char(sym)
		else
			sym = sym - 256              -- 1-based into LEN_BASE
			local length = LEN_BASE[sym] + bs.getbits(LEN_EXTRA[sym])
			local dsym   = decode_sym(bs, disthuff) + 1
			local dist   = DIST_BASE[dsym] + bs.getbits(DIST_EXTRA[dsym])
			local start  = #out - dist + 1
			if start < 1 then error("inflate: distance too far back") end
			for i = 0, length - 1 do
				out[#out + 1] = out[start + i]   -- overlap-safe (appends as it reads)
			end
		end
	end
end

local function read_dynamic_tables(bs)
	local hlit  = bs.getbits(5) + 257
	local hdist = bs.getbits(5) + 1
	local hclen = bs.getbits(4) + 4

	local cl_lengths = {}
	for i = 1, 19 do cl_lengths[i] = 0 end
	for i = 1, hclen do cl_lengths[CL_ORDER[i]] = bs.getbits(3) end
	local cl_huff = build_huffman(cl_lengths, 19)

	-- Decode hlit + hdist code lengths, honouring RLE symbols 16/17/18
	local all = {}
	local total = hlit + hdist
	while #all < total do
		local sym = decode_sym(bs, cl_huff)
		if sym < 16 then
			all[#all + 1] = sym
		elseif sym == 16 then
			local prev = all[#all] or error("inflate: repeat with no previous length")
			for _ = 1, bs.getbits(2) + 3 do all[#all + 1] = prev end
		elseif sym == 17 then
			for _ = 1, bs.getbits(3) + 3  do all[#all + 1] = 0 end
		else -- 18
			for _ = 1, bs.getbits(7) + 11 do all[#all + 1] = 0 end
		end
	end

	local lit_lengths, dist_lengths = {}, {}
	for i = 1, hlit  do lit_lengths[i]  = all[i] end
	for i = 1, hdist do dist_lengths[i] = all[hlit + i] end
	return build_huffman(lit_lengths, hlit), build_huffman(dist_lengths, hdist)
end

-- Inflate a raw DEFLATE stream (RFC 1951). Returns the decompressed string.
function M.inflate(data)
	local bs  = bitstream(data)
	local out = {}
	repeat
		local bfinal = bs.getbit()
		local btype  = bs.getbits(2)
		if btype == 0 then
			bs.align()
			local len  = bs.getbyte() + bs.getbyte() * 256
			bs.getbyte(); bs.getbyte()          -- NLEN (one's complement, unchecked)
			for _ = 1, len do out[#out + 1] = char(bs.getbyte()) end
		elseif btype == 1 then
			local lit, dist = fixed_tables()
			inflate_block(bs, lit, dist, out)
		elseif btype == 2 then
			local lit, dist = read_dynamic_tables(bs)
			inflate_block(bs, lit, dist, out)
		else
			error("inflate: reserved block type 3")
		end
	until bfinal == 1
	return concat(out)
end

-- Inflate a zlib stream (RFC 1950): 2-byte header, DEFLATE body, Adler-32
-- trailer. The header and trailer are skipped; the checksum is not verified.
function M.zlib_decompress(data)
	if #data < 2 then error("inflate: zlib stream too short") end
	local cmf = byte(data, 1)
	local flg = byte(data, 2)
	if cmf % 16 ~= 8 then error("inflate: not a zlib DEFLATE stream (CM~=8)") end
	local start = 3
	if floor(flg / 32) % 2 == 1 then start = 7 end   -- FDICT set → skip DICTID
	-- Drop the 4-byte Adler-32 trailer before feeding the DEFLATE body.
	return M.inflate(data:sub(start, #data - 4))
end

return M
