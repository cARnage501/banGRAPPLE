# payloadv2 and YAA Notes

This document explains what `banGRAPPLE` learned from the Ventura-era `payloadv2` archive chain inside Apple's installer assets. It is written to be useful to two audiences:

- contributors who want the plain-English version first
- implementers who need the exact reconstruction model

The short version is simple:

- the installer payload is not a monolithic DMG
- the `payloadv2` shards are transport fragments
- the real payload is a streamed filesystem archive
- reconstructing it means rebuilding files and directories, not carving a disk image

## Why This Matters

At first glance, Apple's modern installer packages look like a stack of opaque containers:

```text
InstallAssistant.pkg
  -> SharedSupport.dmg
  -> MobileAsset zip
  -> payloadv2/
```

The hard question was whether `payloadv2` hid:

- a sharded DMG
- a patch-only transport
- a private container format
- or a filesystem archive

The answer is now much clearer. `payloadv2` is a filesystem reconstruction stream wrapped in ordered transport shards.

## Executive Summary

The current understanding is:

```text
payload.NNN shards
  -> pbzx wrapper
  -> decoded YAA stream
  -> filesystem objects
  -> regular files, directories, xattrs, and large payload blobs
```

What this means in practice:

- `payload_chunks.txt` gives the shard order
- `payload.000`, `payload.001`, and so on are `pbzx` streams
- decoding those streams yields one continuous YAA archive
- the YAA archive describes a filesystem tree
- large file content is attached through external payload descriptors such as `DATA` and `DATB`

This is enough to say that `payloadv2` is not random binary archaeology anymore. It has a lawful, streamable structure.

## The Artifact Chain

The relevant Apple artifact chain for Phase 1 looks like this:

```text
Apple catalog
  -> installer product metadata
  -> InstallAssistant.pkg
  -> SharedSupport.dmg
  -> MobileAsset zip
  -> AssetData/payloadv2
```

Important detail:

- the main system payload lives under `payloadv2`
- the `BaseSystem` path still appears to be separate and patch-driven

That distinction matters. Reconstructing the main filesystem archive is not the same thing as fully reconstructing the installer boot image.

## What We Confirmed

### 1. `payloadv2` shards are ordered explicitly

`payload_chunks.txt` is the authoritative shard-order table.

That means reconstruction does not need to guess ordering. It can process:

```text
payload.000
payload.001
payload.002
...
```

in the exact order listed by Apple's metadata.

### 2. Every shard is wrapped in `pbzx`

Each `payload.NNN` begins as a `pbzx` stream.

In plain terms, that means each shard is a transport wrapper containing compressed chunks. The wrapper must be decoded before the actual archive bytes appear.

### 3. The decoded stream begins with `YAA1`

The first decoded bytes contain the `YAA1` magic. That is the key format boundary.

This was the major breakthrough because it proved that the installer payload is not simply a chunked disk image. It is a tagged archive of filesystem objects.

### 4. YAA records are object-oriented

The decoded stream contains records that describe:

- directories
- files
- ownership
- mode bits
- timestamps
- extended attributes
- external file payloads

That explains why the archive looked like a mix of path strings and binary blobs. It really is a filesystem build stream.

### 5. Large files are normal records, not a separate format

Large files do not introduce a new container layer. They show up as file records with a `DATB` payload descriptor, which is the large-payload sibling of `DATA`.

Examples observed during traversal:

- `System/Library/Fonts/Apple Color Emoji.ttc`
- `System/Library/KernelCollections/SystemKernelExtensions.kc`
- `System/Library/KernelCollections/BootKernelExtensions.kc`
- `System/Applications/Music.app/Contents/MacOS/Music`
- large linguistic model and tokenizer files

## YAA Record Model

YAA is tag-based. It should not be treated as a fixed C struct.

An observed record looks conceptually like this:

```text
YAA1
declared_length
TYP1
PATP
UID1 / UID2 / UID4
GID1 / GID2 / GID4
MOD2
FLG1 / FLG2 / FLG4
MTMS / MTMT
DATA / DATB / XATA
...
```

Important observed tags:

- `TYP1`: object type
- `PATP`: object path
- `UID1`, `UID2`, `UID4`: user id widths
- `GID1`, `GID2`, `GID4`: group id widths
- `MOD2`: POSIX mode
- `FLG1`, `FLG2`, `FLG4`: flags
- `FLI4`: inline flag-like metadata seen on many large files
- `MTMS`, `MTMT`: timestamps
- `DATA`: smaller external payload
- `DATB`: larger external payload
- `XATA`: extended attribute payload
- `AFT*`, `AFR*`: parsed syntactically, semantics still under study

The current parser treats records as:

- metadata block first
- external payload bytes immediately after metadata
- next record begins after the external payload is consumed

That model has held over many gigabytes of decoded stream position.

## What the Filesystem Looks Like

The archive is not flat. It has recognizable regions.

Early regions are metadata-heavy and directory-rich:

- `System/Applications/...`
- `System/Library/Accessibility/...`
- app bundles, localized resources, plug-ins, signatures

Middle regions move into templates and seeded data:

- `System/Library/Templates/Data/...`
- application support seeds
- template content
- preinstalled asset trees

Later regions become increasingly payload-heavy:

- fonts
- wallpapers
- kernel collections
- framework resources
- machine learning weights
- linguistic models
- tokenizer data
- `iOSSupport` resources

This matters because it means the stream has a topography. Some regions are cheap to parse but noisy. Later regions contain fewer records but much larger attached payloads.

## Structural Map Observations

The descriptor-walk mode added scale instrumentation so the parser could report more than a single “it worked” verdict.

That mode now tracks:

- cumulative skipped payload bytes
- largest payload descriptor seen in a pass
- record-class frequencies by byte region
- first-seen tag families
- first unexpected tag family

This turns the probe into a structural mapper, not just a spot-check parser.

Examples from real runs:

- one pass advanced from about `2.12 GB` to `9.44 GB` of decoded stream offset
- that same pass skipped more than `7.3 GB` of payload bytes
- another pass was dominated by large binary assets but still introduced no new tag families

The key conclusion is that “very large files” and “new format behavior” are not the same thing.

## How To Un-Shard

The phrase “un-shard” is slightly misleading here. The goal is not to glue compressed files together and hope a DMG falls out. The real process is streaming reconstruction.

The deterministic algorithm is:

```text
1. Read payload_chunks.txt
2. Process payload shards in order
3. Decode each shard's pbzx wrapper
4. Treat the decoded bytes as one continuous YAA stream
5. Parse YAA records in sequence
6. Reconstruct filesystem objects from those records
7. For DATA or DATB, consume the attached payload bytes immediately after metadata
```

In other words:

```text
shards -> pbzx decode -> YAA stream -> filesystem tree
```

Not:

```text
shards -> concatenate -> DMG
```

## What “Reconstruct the Filesystem Tree” Means

For each parsed record:

- create the directory if the record is a directory
- create the file if the record is a file
- apply ownership and mode data
- attach xattrs when present
- write file bytes from `DATA` or `DATB`

This is the core un-sharding process.

Some tags are still only syntactically understood, but the main reconstruction path is now clear enough to be implemented safely in a streaming builder.

## What We Have Not Fully Solved Yet

This work solved the main archive chain, but it did not solve everything.

### 1. `BaseSystem` is still separate

The observed `x86_64BaseSystem.dmg` artifact in `payloadv2/basesystem_patches/` is a `BXDIFF50` patch artifact, not a stageable DMG.

That implies a separate reconstruction path:

- canonical base image
- patch layer
- trust/chunk metadata

That path is related to installer boot media, but it is not the same as reconstructing the main filesystem archive.

### 2. Some fields are parsed but not fully named

The parser currently handles:

- `AFT*`
- `AFR*`
- `FLI4`

cleanly enough to keep structural alignment, but their semantics are still under study.

That is acceptable for format acquisition as long as the parser law continues to hold and those fields remain localized and measurable.

### 3. Full replay into a real output tree is still a later step

The repository already proved early-object extraction and partial materialization. A full streamed tree reconstruction in Rust is still a product-facing milestone, not just a research note.

## What The Python Probe Proved

The Python probe is now “done enough” for its intended purpose.

It proved:

- the shard order is deterministic
- `pbzx` decoding is required and understood
- the decoded payload is a YAA archive
- widened UID/GID variants exist and are manageable
- large payload descriptors are normal archive behavior
- the archive remains structurally stable at scale

In short, the probe moved this work from:

- opaque binary archaeology

to:

- a known streaming reconstruction problem

## What This Means For banGRAPPLE

This matters because it changes the implementation path.

The repository does not need to guess whether payload reconstruction is possible. It is possible. The work left is engineering work:

- implement a streaming YAA reader in Rust
- reconstruct files and directories deterministically
- decide which subset of reconstructed assets are needed for installer media
- handle the separate `BaseSystem` patch path intentionally

That is a much better place to be than “poke at random containers and hope.”

## Recommended Next Steps

1. Preserve this document and keep it updated as the canonical reference.
2. Port the minimum viable YAA stream reader into Rust.
3. Add descriptor-only traversal to the Rust side first.
4. Add streamed filesystem reconstruction after the reader is stable.
5. Treat `BaseSystem` patch synthesis as a separate, explicit milestone.

## Bottom Line

The most important conclusion is this:

`payloadv2` is not an unsolved sharding mystery anymore.

It is a deterministic, ordered, `pbzx`-wrapped YAA filesystem archive stream.

That means “un-sharding” is no longer guesswork. It is a streaming reconstruction process that can be implemented deliberately and tested incrementally.
