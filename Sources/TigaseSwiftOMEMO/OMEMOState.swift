//
// OMEMOState.swift
//
// TigaseSwift OMEMO
// Copyright (C) 2022 "Tigase, Inc." <office@tigase.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. Look for COPYING file in the top folder.
// If not, see https://www.gnu.org/licenses/.
//

import Foundation
import TigaseSwift

/// Actor for storing data by OMEMO module
actor OMEMOState {
    
    private var devices: [BareJID: [Int32]] = [:];
    private var devicesFetchError: [BareJID: [Int32]] = [:]
    private var ownBrokenDevices: [Int32] = [];
    private var mamSyncsInProgress: Set<BareJID?> = [];
    private var postponedSessions: [BareJID?: [SignalAddress]] = [:];
    private var postponedHealing: [BareJID?: [SignalAddress]] = [:];
    
    func isAvailable(for jid: BareJID) -> Bool {
        return !(self.devices[jid]?.isEmpty ?? true);
    }
    
    func devices(for jid: BareJID) -> [Int32]? {
        guard let devices = self.devices[jid] else {
            return nil;
        }
        guard let failed = self.devicesFetchError[jid] else {
            return devices;
        }
        return devices.filter({ (deviceId) -> Bool in
            return !failed.contains(deviceId);
        });
    }
    
    func reset() {
        self.devices.removeAll();
    }
    
    func mamSyncStarted(for jid: BareJID?) {
        self.mamSyncsInProgress.insert(jid);
        self.postponedSessions[jid] = [];
    }
    
    func mamSyncFinished(for jid: BareJID?) {
        self.mamSyncsInProgress.remove(jid);
    }
    
    func updateKnownActiveDevices(_ devices: [Int32], for jid: BareJID) {
        self.devices[jid] = devices;
    }
    
    func postponedSession(for jid: BareJID?, address: SignalAddress) -> Bool {
        if mamSyncsInProgress.contains(jid) {
            if var tmp = postponedSessions[jid] {
                tmp.append(address);
                postponedSessions[jid] = tmp;
                return true;
            }
        }
        if mamSyncsInProgress.contains(nil) {
            if var tmp = postponedSessions[nil] {
                tmp.append(address);
                postponedSessions[nil] = tmp;
                return true;
            }
        }
        return false;
    }
    
    func postponedHealing(for jid: BareJID?, address: SignalAddress) -> Bool {
        if mamSyncsInProgress.contains(jid) {
            if var tmp = postponedHealing[jid] {
                tmp.append(address);
                postponedHealing[jid] = tmp;
                return true;
            }
        }
        if mamSyncsInProgress.contains(nil) {
            if var tmp = postponedHealing[nil] {
                tmp.append(address);
                postponedHealing[nil] = tmp;
                return true;
            }
        }
        return false;
    }
    
    func removePostponedSessions(for jid: BareJID?) -> [SignalAddress]? {
        return postponedSessions.removeValue(forKey: jid);
    }
    
    func removePostponedHealing(for jid: BareJID?) -> [SignalAddress]? {
        return postponedHealing.removeValue(forKey: jid);
    }
    
    func markOwnBroken(deviceId: Int32) {
        ownBrokenDevices.append(deviceId);
    }
    
    func clearOwnBrokenDevices() -> [Int32] {
        let devices = ownBrokenDevices;
        ownBrokenDevices = [];
        return devices;
    }
    
    func markDeviceFailed(for jid: BareJID, deviceId: Int32) {
        var devices = self.devicesFetchError[jid] ?? [];
        if !devices.contains(deviceId) {
            devices.append(deviceId);
            self.devicesFetchError[jid] = devices;
        }
    }
    
}

