/*
 * BLA-derived mechanism and code-structure hunting rules. YARA >= 4.3.
 * No BLA names, canary labels, diagnostic prose, or enclave filenames are used
 * as string evidence. Rule names describe research provenance, not attribution.
 * A match is an analysis/triage lead, never a malware verdict.
 * Compressed/encrypted members need bounded extraction before scanning.
 */

private rule BLA_S_Native_Container
{
    condition:
        filesize >= 64 and filesize <= 512MB and
        (
            (uint16(0) == 0x5a4d and uint32(0x3c) >= 64 and uint32(0x3c) <= filesize - 24 and
             uint32(uint32(0x3c)) == 0x00004550) or
            (uint32(0) == 0x464c457f and
             (uint8(4) == 1 or uint8(4) == 2) and
             (uint8(5) == 1 or uint8(5) == 2) and uint8(6) == 1) or
            uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or
            uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or
            ((uint32be(0) == 0xcafebabe or uint32be(0) == 0xcafebabf) and
             uint32be(4) >= 1 and uint32be(4) <= 64 and
             (uint32be(8) == 7 or uint32be(8) == 12 or
              uint32be(8) == 0x01000007 or uint32be(8) == 0x0100000c)) or
            ((uint32(0) == 0xcafebabe or uint32(0) == 0xcafebabf) and
             uint32(4) >= 1 and uint32(4) <= 64 and
             (uint32(8) == 7 or uint32(8) == 12 or
              uint32(8) == 0x01000007 or uint32(8) == 0x0100000c))
        )
}

private rule BLA_S_Electron_Fuse_Run
{
    strings:
        // Real Electron sentinel, required for the targeted fuse reader.
        $fuse = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" ascii
    condition:
        // The targeted reader caps sentinel occurrences before parsing wires.
        // Wire values, spacing and ordering therefore must not be prerequisites.
        BLA_S_Native_Container and #fuse >= 33
}

private rule BLA_S_Dart_Snapshot_Run
{
    strings:
        // Dart snapshot magic + header space + a 32-character hash candidate.
        $snapshot = /\xf5\xf5\xdc\xdc[\x00-\xff]{16}[0-9a-f]{32}/
    condition:
        BLA_S_Native_Container and #snapshot >= 65 and
        // Compare full hashes among the last 128 candidates. Constant loop
        // bounds are required by VT. Appended native plants are near EOF.
        for 65 i in (1..128) : (
            i <= #snapshot and for all j in (1..128) : (
                j >= i or
                for any b in (0..7) : (
                    uint32(@snapshot[#snapshot - j + 1] + 20 + 4*b) !=
                    uint32(@snapshot[#snapshot - i + 1] + 20 + 4*b)
                )
            )
        )
}

private rule BLA_S_Rust_Compiler_Hash_Run
{
    strings:
        $rust = /\/rustc\/[0-9a-f]{40}\//
    condition:
        BLA_S_Native_Container and #rust >= 65 and
        for 65 i in (1..128) : (
            // Avoid treating many paths from ONE normal compiler as a flood.
            i <= #rust and for all j in (1..128) : (
                j >= i or
                for any b in (0..9) : (
                    uint32(@rust[#rust - j + 1] + 7 + 4*b) !=
                    uint32(@rust[#rust - i + 1] + 7 + 4*b)
                )
            )
        )
}

private rule BLA_S_Go_Complete_Framed_Overflow
{
    strings:
        $go = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A ( 04 | 08 ) ( 02 | 03 ) [15] ?? }
        // Canonical Go module envelope, not BLA names or version text.
        $module_start = { 30 77 AF 0C 92 74 08 02 41 E1 C1 07 E6 D6 18 E6 }
        $module_end = { F9 32 43 31 86 18 20 72 00 82 42 10 41 16 D8 F2 }
    condition:
        BLA_S_Native_Container and $go and
        for any i in (1..32) : (
            i <= #go and
            // The short version must be a real printable string. UPX can
            // retain the magic/header followed by encoded or invalid bytes.
            for any p in (34..160) : (
                uint8(@go[#go - i + 1] + 32) == p - 33 and
                for all k in (0..126) : (
                    k >= p - 33 or
                    (uint8(@go[#go - i + 1] + 33 + k) >= 0x20 and
                     uint8(@go[#go - i + 1] + 33 + k) <= 0x7e)
                ) and
                uint8(@go[#go - i + 1] + p) >= 0x80 and
                uint8(@go[#go - i + 1] + p + 1) >= 0x80 and
                for any width in (3..5) : (
                    uint8(@go[#go - i + 1] + p + width - 1) >= 1 and
                    uint8(@go[#go - i + 1] + p + width - 1) < 0x80 and
                    (width == 3 or uint8(@go[#go - i + 1] + p + 2) >= 0x80) and
                    (width < 5 or (uint8(@go[#go - i + 1] + p + 3) >= 0x80 and
                                  uint8(@go[#go - i + 1] + p + 4) <= 0x0f)) and
                    // A singleton integer set binds the decoded value without
                    // a data-dependent loop. Mask bytes beyond this varint.
                    for any declared in (
                        ((uint32(@go[#go - i + 1] + p) & 0x0000007f) |
                         ((uint32(@go[#go - i + 1] + p) & 0x00007f00) >> 1) |
                         ((uint32(@go[#go - i + 1] + p) & 0x007f0000) >> 2) |
                         ((uint32(@go[#go - i + 1] + p) & 0x7f000000) >> 3) |
                         ((uint8(@go[#go - i + 1] + p + 4) & 0x7f) << 28)) &
                        ((1 << (7*width)) - 1)
                    ) : (
                        declared > 1MB and
                        declared <= filesize - (@go[#go - i + 1] + p + width) and
                        $module_start at (@go[#go - i + 1] + p + width) and
                        $module_end at (@go[#go - i + 1] + p + width + declared - 16)
                    )
                )
            )
        )
}

private rule BLA_S_Go_BuildInfo_Size_Trap
{
    strings:
        $go = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A ( 04 | 08 ) ( 02 | 03 ) [15] ?? }
    condition:
        BLA_S_Native_Container and
        (
            BLA_S_Go_Complete_Framed_Overflow or
            // Deliberately impossible version-length claims are a different
            // mechanism from a complete oversized module. They need another
            // runtime signal in every public rule that uses this helper.
            for any i in (1..32) : (
                i <= #go and
                uint8(@go[#go - i + 1] + 32) >= 0x80 and
                uint8(@go[#go - i + 1] + 33) >= 0x80 and
                (
                    (uint8(@go[#go - i + 1] + 34) >= 0x40 and
                     uint8(@go[#go - i + 1] + 34) < 0x80 and
                     ((uint8(@go[#go - i + 1] + 32) & 0x7f) |
                      ((uint8(@go[#go - i + 1] + 33) & 0x7f) << 7) |
                      ((uint8(@go[#go - i + 1] + 34) & 0x7f) << 14)) > 1MB) or
                    (uint8(@go[#go - i + 1] + 34) >= 0x80 and
                     uint8(@go[#go - i + 1] + 35) >= 1 and
                     uint8(@go[#go - i + 1] + 35) < 0x80) or
                    (uint8(@go[#go - i + 1] + 34) >= 0x80 and
                     uint8(@go[#go - i + 1] + 35) >= 0x80 and
                     uint8(@go[#go - i + 1] + 36) >= 1 and
                     uint8(@go[#go - i + 1] + 36) <= 0x0f)
                )
            )
        )
}

rule BLA_Deep_Native_MultiRuntime_Exhaustion
{
    meta:
        description = "Native file with multiple dense runtime-parser exhaustion plants"
        confidence = "high for the structural combination; BLA attribution requires context"
        reference = "https://github.com/qybaihe/bla/blob/8cf27e34cc3fb1ba85c463a3f18743afdd571ea8/src/shields/formats/native.ts"
        revision = 2
    condition:
        BLA_S_Native_Container and
        (
            (BLA_S_Electron_Fuse_Run and BLA_S_Dart_Snapshot_Run) or
            (BLA_S_Electron_Fuse_Run and BLA_S_Rust_Compiler_Hash_Run) or
            (BLA_S_Dart_Snapshot_Run and BLA_S_Rust_Compiler_Hash_Run) or
            (BLA_S_Go_BuildInfo_Size_Trap and
             (BLA_S_Electron_Fuse_Run or BLA_S_Dart_Snapshot_Run or BLA_S_Rust_Compiler_Hash_Run))
        )
}

rule BLA_Deep_Go_BuildInfo_Length_Overflow
{
    meta:
        description = "Framed Go module overflow or oversized version claim, with another runtime overflow"
        confidence = "corroborated technique hunting; not a standalone BLA attribution"
        reference = "https://github.com/qybaihe/bla/blob/8cf27e34cc3fb1ba85c463a3f18743afdd571ea8/src/shields/formats/go-flutter-exhaustion.ts"
        revision = 2
    condition:
        BLA_S_Native_Container and BLA_S_Go_BuildInfo_Size_Trap and
        (BLA_S_Electron_Fuse_Run or BLA_S_Dart_Snapshot_Run or BLA_S_Rust_Compiler_Hash_Run)
}

rule BLA_Deep_Electron_Fuse_Inventory_Overflow
{
    meta:
        description = "Native file exceeds the targeted reader's 32 Electron-sentinel limit"
        confidence = "technique hunting; synthetic fixtures can match"
        revision = 1
    condition:
        BLA_S_Native_Container and BLA_S_Electron_Fuse_Run
}

rule BLA_Deep_Dart_Snapshot_Hash_Overflow
{
    meta:
        description = "Native file with more than 64 distinct Dart snapshot hashes"
        confidence = "technique hunting; not unique to BLA"
        revision = 1
    condition:
        BLA_S_Native_Container and BLA_S_Dart_Snapshot_Run
}

rule BLA_Deep_Rust_Compiler_Hash_Overflow
{
    meta:
        description = "Native file with more than 64 distinct Rust compiler hashes"
        confidence = "technique hunting; multi-toolchain bundles can match"
        revision = 1
    condition:
        BLA_S_Native_Container and BLA_S_Rust_Compiler_Hash_Run
}

rule BLA_Deep_GGUF_Nested_Array_Overflow
{
    meta:
        description = "GGUF metadata key followed by an excessive run of nested ARRAY frames"
        confidence = "technique hunting; not unique to BLA"
        reference = "https://github.com/qybaihe/bla/blob/8cf27e34cc3fb1ba85c463a3f18743afdd571ea8/src/shields/formats/model.ts"
        revision = 1
    strings:
        $array = { 09 00 00 00 ?? ?? ?? ?? 00 00 00 00 }
    condition:
        filesize >= 420 and filesize <= 512MB and
        uint32(0) == 0x46554747 and (uint32(4) == 2 or uint32(4) == 3) and
        (uint32(16) > 0 or uint32(20) > 0) and #array >= 33 and
        for any i in (1..256) : (
            i + 32 <= #array and
            @array[i] >= 24 and
            // Verify a length-prefixed metadata key and its ARRAY value type.
            // The key's text is unconstrained and the leaf value is ignored.
            uint32(@array[i] - 4) == 9 and
            for any n in (1..128) : (
                @array[i] >= 36 + n and
                uint32(@array[i] - 12 - n) == n and
                uint32(@array[i] - 8 - n) == 0 and
                for all k in (0..127) : (
                    k >= n or
                    (uint8(@array[i] - 4 - n + k) >= 0x20 and
                     uint8(@array[i] - 4 - n + k) <= 0x7e)
                )
            ) and
            for all j in (0..31) : (
                @array[i + j + 1] == @array[i + j] + 12 and
                uint32(@array[i + j] + 4) >= 1 and uint32(@array[i + j] + 4) <= 65536
            ) and
            uint32(@array[i + 32] + 4) >= 1 and uint32(@array[i + 32] + 4) <= 65536
        )
}

rule BLA_Deep_JavaScript_Semantic_Budget_Tarpit
{
    meta:
        description = "Co-located alias explosion, recursive getters and additive growth chain"
        confidence = "code-structure hunting; variable and property names are unconstrained"
        reference = "https://github.com/qybaihe/bla/blob/8cf27e34cc3fb1ba85c463a3f18743afdd571ea8/src/shields/tarpit/tarpit-generator.ts"
        revision = 1
    strings:
        $alias = /(const|let|var)[ \t]+[$A-Za-z_][$A-Za-z_0-9]{0,95}\s*=\s*[$A-Za-z_][$A-Za-z_0-9]{0,95}\s*\?\s*[$A-Za-z_][$A-Za-z_0-9]{0,95}\?\.[$A-Za-z_][$A-Za-z_0-9]{0,95}\s*:\s*[$A-Za-z_][$A-Za-z_0-9]{0,95}\?\.[$A-Za-z_][$A-Za-z_0-9]{0,95}/
        $getter = /get[ \t]+[$A-Za-z_][$A-Za-z_0-9]{0,95}\(\s*\)\s*\{\s*return[ \t]+this\[[$A-Za-z_][$A-Za-z_0-9]{0,95}\]\.[$A-Za-z_][$A-Za-z_0-9]{0,95}\s*;?\s*\}/
        $growth = /(const|let|var)[ \t]+[$A-Za-z_][$A-Za-z_0-9]{0,95}\s*=\s*[$A-Za-z_][$A-Za-z_0-9]{0,95}\s*\+\s*[$A-Za-z_][$A-Za-z_0-9]{0,95}\s*;/
    condition:
        filesize >= 1KB and filesize <= 64MB and
        #alias >= 24 and #getter >= 12 and #growth >= 18 and
        for any i in (1..128) : (
            i + 23 <= #alias and
            #alias in (@alias[i]..@alias[i] + 32KB) >= 24 and
            #getter in (@alias[i]..@alias[i] + 32KB) >= 12 and
            #growth in (@alias[i]..@alias[i] + 32KB) >= 18
        )
}

rule BLA_Deep_Python_Decoy_State_Graph
{
    meta:
        description = "Dense function-name hash peer graph paired with mirrored byte mixing"
        confidence = "code-structure hunting; generated identifier names are unconstrained"
        reference = "https://github.com/qybaihe/bla/blob/8cf27e34cc3fb1ba85c463a3f18743afdd571ea8/src/shields/tarpit/tarpit-generator.ts"
        revision = 1
    strings:
        $peers = /hash\([A-Za-z_][A-Za-z_0-9]{0,127}\.__name__\)[ \t]*\^[ \t]*hash\([A-Za-z_][A-Za-z_0-9]{0,127}\.__name__\)/
        $from_bytes = /int\.from_bytes\([A-Za-z_][A-Za-z_0-9]{0,127},[ \t]*["']little["']\)/
        $mirror = /\[[ \t]*7[ \t]*-[ \t]*[A-Za-z_][A-Za-z_0-9]{0,127}[ \t]*\][ \t]*=[ \t]*\(?[A-Za-z_][A-Za-z_0-9]{0,127}[ \t]*>>[ \t]*8\)?[ \t]*&[ \t]*(0xFF|255)/
        $mask = /&[ \t]*(0xFFFFFFFF|4294967295)/
    condition:
        filesize >= 1KB and filesize <= 32MB and
        #peers >= 5 and #mask >= 12 and
        $from_bytes and $mirror and
        for any i in (1..128) : (
            i + 4 <= #peers and
            #peers in (@peers[i]..@peers[i] + 64KB) >= 5 and
            $from_bytes in (@peers[i]..@peers[i] + 64KB) and
            $mirror in (@peers[i]..@peers[i] + 64KB)
        )
}

rule BLA_Deep_PTX_Stub_Kernel_Flood
{
    meta:
        description = "PTX module containing many similarly shaped parameter-loading return stubs"
        confidence = "technique hunting; generated names and diagnostic comments are ignored"
        reference = "https://github.com/qybaihe/bla/blob/8cf27e34cc3fb1ba85c463a3f18743afdd571ea8/src/shields/formats/gpu-ptx.ts"
        revision = 1
    strings:
        $version = ".version "
        $target = ".target "
        $stub = /\.visible\s+\.entry\s+[A-Za-z_$][A-Za-z_$0-9]{0,127}\(\s*\.param\s+\.u64\s+[A-Za-z_$][A-Za-z_$0-9]{0,127}\)\s*\{\s*\.reg\s+\.b64\s+%[A-Za-z_][A-Za-z_0-9]{0,31}<[1-8]>;\s*ld\.param\.u64\s+%[A-Za-z_][A-Za-z_0-9]{0,31},\s*\[[A-Za-z_$][A-Za-z_$0-9]{0,127}\];[^\x00]{0,192}ret;\s*\}/
    condition:
        filesize >= 1KB and filesize <= 32MB and
        $version in (0..2048) and $target in (0..2048) and
        #stub >= 12
}

rule BLA_Deep_Transport_Ambiguity_Cluster
{
    meta:
        description = "Multiple single-slash credential URLs plus conflicting duplicate-query URLs"
        confidence = "technique hunting; URL/security test corpora may match"
        reference = "https://github.com/qybaihe/bla/blob/8cf27e34cc3fb1ba85c463a3f18743afdd571ea8/src/shields/deception/canary-honeypot.ts"
        revision = 1
    strings:
        $ambiguous = /https?:\/[A-Za-z0-9_.%~-]{1,96}:[A-Za-z0-9_.%~-]{1,128}@[A-Za-z0-9_.-]{1,128}\/[A-Za-z0-9_.\/%-]{1,128}/
        $query = /https?:\/\/[A-Za-z0-9_.-]{1,128}\/[A-Za-z0-9_.\/%-]{1,128}\?[A-Za-z_][A-Za-z_0-9.-]{0,31}=[0-9]{1,8}&(amp;)?[A-Za-z_][A-Za-z_0-9.-]{0,31}=[0-9]{1,8}/
    condition:
        filesize >= 256 and filesize <= 64MB and
        #ambiguous >= 2 and #query >= 2 and
        for 2 q in (1..128) : (
            q <= #query and
            // Pack delimiter offset (t >> 5) and key length ((t & 31) + 1)
            // into one iterator to stay within YARA's four-level loop limit.
            for any t in (256..8703) : (
                (t >> 5) < !query[q] and
                uint8(@query[q] + (t >> 5)) == 0x3f and
                uint8(@query[q] + (t >> 5) + (t & 31) + 2) == 0x3d and
                    // v packs first-value length ((v & 7) + 1) and the
                    // separator's extra width (4*(v >> 3)): '&' or '&amp;'.
                    for any v in (0..15) : (
                        uint8(@query[q] + (t >> 5) + (t & 31) + (v & 7) + 4) == 0x26 and
                        uint8(@query[q] + (t >> 5) + 2*(t & 31) + (v & 7) + 6 + 4*(v >> 3)) == 0x3d and
                        for all b in (0..31) : (
                            b > (t & 31) or
                            uint8(@query[q] + (t >> 5) + 1 + b) ==
                            uint8(@query[q] + (t >> 5) + (t & 31) + (v & 7) + 5 + 4*(v >> 3) + b)
                        ) and
                        (
                            !query[q] - (t >> 5) - 2*(t & 31) - (v & 7) - 7 - 4*(v >> 3) != (v & 7) + 1 or
                            for any d in (0..7) : (
                                d <= (v & 7) and
                                uint8(@query[q] + (t >> 5) + (t & 31) + 3 + d) !=
                                uint8(@query[q] + (t >> 5) + 2*(t & 31) + (v & 7) + 7 + 4*(v >> 3) + d)
                            )
                        )
                    )
            )
        )
}
