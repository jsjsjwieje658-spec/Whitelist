//
//  Common.swift
//  Whitelist
//
//  Created by Hariz Shirazi on 2023-02-03.
//
//  Updated: Now uses Dopamine's ClearSword kernel exploit for file operations.
//  The old CVE-2022-46689 race condition is kept as fallback.
//

import Foundation
import os.log

public func print(_ items: Any..., separator: String = " ", terminator: String = "\n") {
    let data = items.map { "\($0)" }.joined(separator: separator)
    consoleManager.print(data)
    Swift.print(data, terminator: terminator)
}

public func conditionalPrint(_ items: Any..., c: Bool, separator: String = " ", terminator: String = "\n") {
    if c {
        let data = items.map { "\($0)" }.joined(separator: separator)
        consoleManager.print(data)
        Swift.print(data, terminator: terminator)
    }
}

let blankPlist = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8vQXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8ZGljdC8+CjwvcGxpc3Q+Cg=="

// Backward compatibility
var blankplist: String { return blankPlist }

// MARK: - Primary File Overwrite (Kernel Exploit)

/// Overwrite a file using kernel exploit primitives.
/// This is the PRIMARY method when kernel exploit is available.
/// Falls back to (1) a direct POSIX write when the process is already
/// unsandboxed (TrollStore / vphone jb VM / FDA install) and then
/// (2) the CVE-2022-46689 race condition.
func overwriteFileWithKernelExploit(path: String, data: Data) -> Bool {
    let manager = KernelExploitManager.shared

    if manager.isExploitSuccessful {
        // Use kernel write primitives
        let success = manager.overwriteFile(path: path, data: data)
        if success {
            print("Successfully overwrote via kernel exploit: \(path)")
        } else {
            print("Kernel exploit write failed for \(path)")
        }
        return success
    }

    os_log(.debug, "Kernel exploit not available - trying direct write (TrollStore/FDA)")
    if directWriteAsUnsandboxed(path: path, data: data) {
        return true
    }
    return overwriteFileWithLegacyExploit(path: path, replacementData: data)
}

// MARK: - Direct Write (already-unsandboxed installs)

/// Plain POSIX create/overwrite for installs that run without a sandbox.
/// TrollStore apps and vphone `jb` VMs are unsandboxed + root-ish, so they
/// can simply create/overwrite the ban databases without any exploit.
/// A sandboxed sideload fails at open/stat and the caller falls through.
func directWriteAsUnsandboxed(path: String, data: Data) -> Bool {
    var sb = stat()
    if stat("/private/var/db", &sb) != 0 {
        return false
    }

    // Create missing parents (fresh devices have no MobileIdentityData files)
    let dir = (path as NSString).deletingLastPathComponent
    if !FileManager.default.fileExists(atPath: dir) {
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    }

    let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)
    guard fd >= 0 else {
        print("Direct write: open(\(path)) failed: \(String(cString: strerror(errno)))")
        return false
    }
    defer { close(fd) }
    let written = data.withUnsafeBytes { raw -> Int in
        guard let base = raw.baseAddress else { return -1 }
        return write(fd, base, data.count)
    }
    if written == data.count {
        print("Successfully wrote directly (already unsandboxed): \(path)")
        return true
    }
    return false
}

// MARK: - Legacy File Overwrite (CVE-2022-46689)

/// Legacy file overwrite using CVE-2022-46689 race condition.
/// Kept as fallback when kernel exploit is not available.
func overwriteFileWithLegacyExploit(path: String, replacementData: Data) -> Bool {
    // The CVE race can only overwrite EXISTING files - report a missing
    // target precisely instead of a generic "could not open" error.
    if !FileManager.default.fileExists(atPath: path) {
        print("Legacy method: \(path) does not exist on this device (no bans stored - nothing to overwrite).")
        return false
    }
    // open and map original font
    let fd = open(path, O_RDONLY | O_CLOEXEC)
    if fd == -1 {
        print("Could not open target file: \(path)")
        return false
    }
    defer { close(fd) }
    // check size of font
    let originalFileSize = lseek(fd, 0, SEEK_END)
    guard originalFileSize >= replacementData.count else {
        print("Original file: \(originalFileSize)")
        print("Replacement file: \(replacementData.count)")
        print("File too big!")
        return false
    }
    lseek(fd, 0, SEEK_SET)
    
    // Map the file we want to overwrite so we can mlock it
    let fileMap = mmap(nil, replacementData.count, PROT_READ, MAP_SHARED, fd, 0)
    if fileMap == MAP_FAILED {
        print("Failed to map")
        return false
    }
    // mlock so the file gets cached in memory
    guard mlock(fileMap, replacementData.count) == 0 else {
        print("Failed to mlock")
        return true
    }
    
    // for every 16k chunk, rewrite
    print(Date())
    for chunkOff in stride(from: 0, to: replacementData.count, by: 0x4000) {
        print(String(format: "%lx", chunkOff))
        let dataChunk = replacementData[chunkOff..<min(replacementData.count, chunkOff + 0x4000)]
        var overwroteOne = false
        for _ in 0..<2 {
            let overwriteSucceeded = dataChunk.withUnsafeBytes { dataChunkBytes in
                return unaligned_copy_switch_race(
                    fd, Int64(chunkOff), dataChunkBytes.baseAddress, dataChunkBytes.count)
            }
            if overwriteSucceeded {
                overwroteOne = true
                print("Successfully overwrote via legacy method!")
                break
            }
            print("try again?!")
        }
        guard overwroteOne else {
            print("Failed to overwrite")
            return false
        }
    }
    print(Date())
    print("Successfully overwrote via legacy method!")
    return true
}

// MARK: - Unified Blacklist Operations

/// Overwrite the blacklist file (Rejections.plist).
/// Uses kernel exploit if available, falls back to legacy method.
func overwriteBlacklist() -> Bool {
    let data = Data(base64Encoded: blankPlist)!
    return overwriteFileWithKernelExploit(
        path: "/private/var/db/MobileIdentityData/Rejections.plist",
        data: data
    )
}

/// Overwrite the banned apps list (AuthListBannedUpps.plist).
func overwriteBannedApps() -> Bool {
    let data = Data(base64Encoded: blankPlist)!
    return overwriteFileWithKernelExploit(
        path: "/private/var/db/MobileIdentityData/AuthListBannedUpps.plist",
        data: data
    )
}

/// Overwrite the CD hashes list (AuthListBannedCdHashes.plist).
func overwriteCdHashes() -> Bool {
    let data = Data(base64Encoded: blankPlist)!
    return overwriteFileWithKernelExploit(
        path: "/private/var/db/MobileIdentityData/AuthListBannedCdHashes.plist",
        data: data
    )
}

/// Read a file's contents. Directory targets (Omega persistence) are
/// reported as such instead of a confusing read error.
func readFile(path: String) -> String? {
    var sb = stat()
    if stat(path, &sb) == 0 && (sb.st_mode & S_IFMT) == S_IFDIR {
        return "(directory - Omega persistence active, the system cannot store ban entries here)"
    }
    guard let contents = try? String(contentsOfFile: path) else {
        return nil
    }
    return contents
}

// MARK: - Exploit Status

/// Get current exploit status for display.
func getExploitStatus() -> String {
    let manager = KernelExploitManager.shared
    if manager.isExploitSuccessful {
        return "✅ Kernel exploit active"
    } else if manager.isExploitRunning {
        return "⏳ Kernel exploit running..."
    } else if !manager.isSupported {
        // Anti-freeze: unsupported devices never arm the kernel exploit;
        // the app runs purely on the legacy CVE-2022-46689 method.
        return "🐢 No kernel exploit for this device - legacy method"
    } else if let error = manager.lastError {
        return "❌ \(error)"
    } else {
        return "⚠️ Kernel exploit not initialized"
    }
}
