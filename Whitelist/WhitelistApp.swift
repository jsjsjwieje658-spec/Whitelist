//
//  WhitelistApp.swift
//  Whitelist
//
//  Created by Hariz Shirazi on 2023-02-03.
//
//  Updated: Integrates Dopamine's ClearSword kernel exploit for
//  robust file overwriting on iOS 15.0-18.7.1.
//

import SwiftUI
import os.log
import LocalConsole
let consoleManager = LCManager.shared
let launchedBefore = UserDefaults.standard.bool(forKey: "launchedBefore")

var isUnsandboxed = false

@main
struct WhitelistApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    var body: some Scene {
        WindowGroup {
            ContentView()
                .onAppear {
                    // Initialize kernel exploit subsystem
                    initializeKernelExploit()
                    
                    if #available(iOS 16.2, *) {
#if targetEnvironment(simulator)
#else
                        print("iOS 16.2+ detected, using kernel exploit method")
                        // Kernel exploit works on iOS 16.2+ (unlike legacy CVE-2022-46689)
                        // The ClearSword exploit from Dopamine supports iOS 15.0-18.7.1
                        os_log(.info, "INFO: Using kernel exploit for iOS 16.2+")
#endif
                    } else {
                        do {
                            // TrollStore method
                            print("Checking if installed with TrollStore...")
                            try FileManager.default.contentsOfDirectory(at: URL(fileURLWithPath: "/var/mobile/Library/Caches"), includingPropertiesForKeys: nil)
                            os_log(.info, "INFO: TrollStore detected!")
                            isUnsandboxed = true
                        } catch {
                            isUnsandboxed = false
                            // MDC / Kernel exploit method
                            if #available(iOS 15, *) {
                                print("Attempting kernel-based sandbox escape...")
                                let manager = KernelExploitManager.shared
                                if manager.isExploitSuccessful {
                                    // Kernel exploit already succeeded during init
                                    isUnsandboxed = true
                                    os_log(.info, "INFO: Kernel exploit provides sandbox escape")
                                } else {
                                    // Fall back to legacy grant_full_disk_access
                                    print("Falling back to legacy sandbox escape...")
                                    grant_full_disk_access() { error in
                                        if (error != nil) {
                                            print("Unable to escape sandbox! Error: ", String(describing: error?.localizedDescription ?? "unknown?!"))
                                            os_log(.fault, "ERROR: unsandbox failed!")
                                            UIApplication.shared.alert(title: "Access Error", body: "Error: \(String(describing: error?.localizedDescription))\nPlease close the app and retry.", withButton: false)
                                            isUnsandboxed = false
                                        }
                                    }
                                    os_log(.info, "INFO: Attempted sandbox escape via legacy method.")
                                    isUnsandboxed = true
                                }
                            } else {
                                print("iOS version too old, not supported")
                                os_log(.error, "ERROR: Running below iOS 15")
                                UIApplication.shared.alert(title: "Exploit Not Supported", body: "Please install via TrollStore")
                                isUnsandboxed = false
                            }
                        }
                    }
                    
                    // Check for updates
                    if let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String, let url = URL(string: "https://api.github.com/repos/BomberFish/Whitelist/releases/latest") {
                        let task = URLSession.shared.dataTask(with: url) {(data, response, error) in
                            guard let data = data else { return }
                            
                            if let json = try? JSONSerialization.jsonObject(with: data, options: .mutableContainers) as? [String: Any] {
                                if (json["tag_name"] as? String)?.replacingOccurrences(of: "v", with: "").compare(version, options: .numeric) == .orderedDescending {
                                    UIApplication.shared.confirmAlert(title: "Update available!", body: "A new app update is available, do you want to visit the releases page?", onOK: {
                                        UIApplication.shared.open(URL(string: "https://github.com/BomberFish/Whitelist/releases/latest")!)
                                    }, noCancel: false)
                                }
                            }
                        }
                        task.resume()
                    }
                    
                    consoleManager.isVisible = UserDefaults.standard.bool(forKey: "LCEnabled")
                    if launchedBefore  {
                        print("Not first launch.")
                    } else {
                        print("First launch, setting UserDefault.")
                        UIApplication.shared.choiceAlert(title: "Analytics", body: "Allow AppCommander to send anonymized data to improve your experience?", yesAction: {
                            UserDefaults.standard.set(1, forKey: "analyticsLevel")
                            UserDefaults.standard.set(true, forKey: "launchedBefore")
                        }, noAction: {
                            UserDefaults.standard.set(0, forKey: "analyticsLevel")
                            UserDefaults.standard.set(true, forKey: "launchedBefore")
                        })
                    }
                }
        }
    }
    
    /// Initialize the kernel exploit subsystem.
    /// This runs the ClearSword exploit from Dopamine in the background.
    private func initializeKernelExploit() {
        let manager = KernelExploitManager.shared
        
        // Don't re-initialize if already successful
        guard !manager.isExploitSuccessful else { return }
        
        os_log(.info, "Initializing kernel exploit (ClearSword)...")
        
        manager.runExploit { success, error in
            if success {
                os_log(.info, "Kernel exploit ready! KRW primitives established.")
                
                // Attempt to unsandbox using kernel primitives
                let unsandboxed = manager.unsandbox()
                if unsandboxed {
                    isUnsandboxed = true
                    os_log(.info, "Sandbox bypassed via kernel exploit")
                } else {
                    os_log(.warning, "Kernel unsandbox failed, will use legacy method if needed")
                }
            } else {
                os_log(.error, "Kernel exploit initialization failed: %{public}@", error ?? "unknown")
                os_log(.info, "Will fall back to legacy CVE-2022-46689 method")
            }
        }
    }
}
