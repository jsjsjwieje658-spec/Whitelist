//
//  ContentView.swift
//  Whitelist
//
//  Created by Hariz Shirazi on 2023-02-03.
//
//  Updated: Shows kernel exploit status and uses unified exploit manager.
//

import SwiftUI
import os.log

struct ContentView: View {
    @State var blacklist = true
    @State var banned: Bool = UserDefaults.standard.bool(forKey: "BannedEnabled")
    @State var cdHash: Bool = UserDefaults.standard.bool(forKey: "CdEnabled")
    @State var persistMode: Bool = UserDefaults.standard.bool(forKey: "OmegaPersistMode")
    @State var inProgress = false
    @State var message = ""
    @State var banned_success = false
    @State var blacklist_success = false
    @State var hash_success = false
    @State var success = false
    @State var success_message = ""
    @State var exploitStatus = getExploitStatus()
    @ObservedObject var backgroundController = BackgroundFileUpdaterController.shared
    @State private var bgUpdateInterval: Double = UserDefaults.standard.double(forKey: "BackgroundUpdateInterval")
    @State var runInBackground: Bool = UserDefaults.standard.bool(forKey: "BackgroundApply")

    @State var bgUpdateIntervalDisplayTitles: [Double: String] = [
        120.0: "Frequent",
        600.0: "Power Saver"
    ]
    
    @State var bgUpdateIntervalIcons: [Double: String] = [
        120.0: "bolt.badge.clock",
        600.0: "leaf"
    ]
    
    let appVersion = ((Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown") + " (" + (Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "Unknown") + ")")
    var body: some View {
        NavigationView {
            List {
                // Exploit Status Section
                Section {
                    HStack {
                        Text("Exploit Status")
                        Spacer()
                        Text(exploitStatus)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .onAppear {
                        // Refresh status periodically
                        Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
                            exploitStatus = getExploitStatus()
                        }
                    }
                } header: {
                    Label("System", systemImage: "cpu")
                }
                
                Section {
                    Button(
                        action: {
                            os_log(.debug, "FG: Applying!")
                            Haptic.shared.play(.heavy)
                            inProgress = true
                            
                            // Try kernel exploit first
                            let manager = KernelExploitManager.shared
                            
                            if manager.isExploitSuccessful {
                                // Use kernel-based removal (optionally with
                                // Omega-style directory persistence)
                                let result = persistMode
                                    ? manager.persistAllBlacklists()
                                    : manager.removeAllBlacklists()
                                success = result.0
                                success_message = result.1
                            } else {
                                // Fall back to legacy method
                                if banned {
                                    banned_success = overwriteBannedApps()
                                }
                                if cdHash {
                                    hash_success = overwriteCdHashes()
                                } else {
                                    banned_success = false
                                    hash_success = false
                                }
                                success = overwriteBlacklist()
                                
                                if banned_success && hash_success {
                                    success_message = "Successfully removed: Blacklist, Banned Apps, CDHashes\nDidn't overwrite: none"
                                } else if !banned_success && hash_success {
                                    success_message = "Successfully removed: Blacklist, CDHashes\nDidn't overwrite: Banned Apps"
                                } else if banned_success && !hash_success {
                                    success_message = "Successfully removed: Blacklist, Banned Apps\nDidn't overwrite: CDHashes"
                                } else {
                                    success_message = "Successfully removed: Blacklist\nDidn't overwrite: Banned Apps, CDHashes"
                                }
                            }
                            
                            if success {
                                UIApplication.shared.alert(title: "Success", body: success_message, withButton: true)
                                inProgress = false
                                Haptic.shared.notify(.success)
                                os_log(.debug, "FG: Success! See UI for details.")
                            } else {
                                // Include the concrete failure reason (which
                                // file, which errno) instead of a generic text.
                                UIApplication.shared.alert(title: "Error", body: "An error occurred while writing to the file.\n\n\(success_message)", withButton: true)
                                os_log(.debug, "FG: Error! See UI for details.")
                                inProgress = false
                                Haptic.shared.notify(.error)
                            }
                            // UPDATE BACKGROUND
                            if runInBackground {
                                os_log(.debug, "Updating BG")
                                backgroundController.updateFiles()
                            }
                        },
                        label: {
                            HStack {
                                ProgressView()
                                    .progressViewStyle(.circular)
                                    .tint(.white)
                                    .opacity(inProgress ? 1 : 0)
                                Text(inProgress ? "Applying..." : "Apply")
                                    .fontWeight(.semibold)
                                    .frame(maxWidth: .infinity, minHeight: 38)
                                    .animation(.easeInOut(duration: 0.1), value: inProgress)
                            }
                            .foregroundColor(.white)
                            .listRowBackground(inProgress ? Color.gray : Color.accentColor)
                        }
                    ).disabled(inProgress)
                } header: {
                    Label("Actions", systemImage: "bolt")
                }
                
                Section {
                    Toggle("Banned Apps", isOn: $banned)
                        .onChange(of: banned) { value in
                            UserDefaults.standard.set(value, forKey: "BannedEnabled")
                            Haptic.shared.play(.light)
                        }
                    Toggle("CDHashes", isOn: $cdHash)
                        .onChange(of: cdHash) { value in
                            UserDefaults.standard.set(value, forKey: "CdEnabled")
                            Haptic.shared.play(.light)
                        }
                    Toggle("Omega persistence (replace files with directories)", isOn: $persistMode)
                        .onChange(of: persistMode) { value in
                            UserDefaults.standard.set(value, forKey: "OmegaPersistMode")
                            Haptic.shared.play(.light)
                        }
                } header: {
                    Label("Options", systemImage: "gearshape")
                }
                
                Section {
                    Toggle("Background Update", isOn: $runInBackground)
                        .onChange(of: runInBackground) { value in
                            UserDefaults.standard.set(value, forKey: "BackgroundApply")
                            Haptic.shared.play(.light)
                            if value {
                                backgroundController.updateFiles()
                            }
                        }
                    
                    if runInBackground {
                        ForEach(bgUpdateIntervalDisplayTitles.sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                            Button(action: {
                                bgUpdateInterval = key
                                UserDefaults.standard.set(key, forKey: "BackgroundUpdateInterval")
                                backgroundController.time = key
                                Haptic.shared.play(.light)
                            }) {
                                HStack {
                                    Label(value, systemImage: bgUpdateIntervalIcons[key] ?? "questionmark")
                                    Spacer()
                                    if bgUpdateInterval == key {
                                        Image(systemName: "checkmark")
                                            .foregroundColor(.blue)
                                    }
                                }
                            }
                            .foregroundColor(.primary)
                        }
                    }
                } header: {
                    Label("Settings", systemImage: "gear")
                }
                
                Section {
                    NavigationLink {
                        FileContentsView()
                    } label: {
                        Label("View contents of blacklist files", systemImage: "doc.text")
                    }
                } header : {
                    Label("Advanced", systemImage: "wrench.and.screwdriver")
                }
                
                Section(header: Text("Whitelist " + appVersion + "\nMade with ❤️ by BomberFish")) {}.textCase(nil)
                    .toolbar {
                        NavigationLink {
                            SettingsView()
                        } label: {
                            Label("", systemImage: "gear")
                        }
                    }
            }
            .navigationTitle("Whitelist")
        }
        .navigationTitle("Whitelist")
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
