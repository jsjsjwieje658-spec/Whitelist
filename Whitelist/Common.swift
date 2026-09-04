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
/// Falls back to CVE-2022-46689 race condition if kernel exploit fails.
func overwriteFileWithKernelExploit(path: String, data: Data) -> Bool {
    let manager = KernelExploitManager.shared
    
    guard manager.isExploitSuccessful else {
        os_log(.debug, "Kernel exploit not available, falling back to legacy method")
        return overwriteFileWithLegacyExploit(path: path, data: data)
    }
    
    // Use kernel write primitives
    let success = manager.overwriteFile(path: path, data: data)
    if success {
        print("Successfully overwrote via kernel exploit: \(path)")
    } else {
        print("Kernel exploit write failed for \(path)")
    }
    return success
}

// MARK: - Legacy File Overwrite (CVE-2022-46689)

/// Legacy file overwrite using CVE-2022-46689 race condition.
/// Kept as fallback when kernel exploit is not available.
func overwriteFileWithLegacyExploit(path: String, replacementData: Data) -> Bool {
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

/// Read a file's contents.
func readFile(path: String) -> String? {
    return (try? String?(String(contentsOfFile: path)) ?? "ERROR: Could not read from file! Are you running in the simulator or not unsandboxed?")
}

// MARK: - Exploit Status

/// Get current exploit status for display.
func getExploitStatus() -> String {
    let manager = KernelExploitManager.shared
    if manager.isExploitSuccessful {
        return "✅ Kernel exploit active"
    } else if manager.isExploitRunning {
        return "⏳ Kernel exploit running..."
    } else if let error = manager.lastError {
        return "❌ \(error)"
    } else {
        return "⚠️ Kernel exploit not initialized"
    }
}
