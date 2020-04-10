//
// SignalAddress.swift
//
// TigaseSwift OMEMO
// Copyright (C) 2019 "Tigase, Inc." <office@tigase.com>
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
import libsignal

open class SignalAddress: Hashable, CustomStringConvertible {
    
    public static func == (lhs: SignalAddress, rhs: SignalAddress) -> Bool {
        return lhs.name == rhs.name && lhs.deviceId == rhs.deviceId;
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(name);
        hasher.combine(deviceId);
    }
    
    public let name: String;
    public let deviceId: Int32;
    
    fileprivate let nameBytes: UnsafeMutablePointer<Int8>;
    public let address: UnsafeMutablePointer<signal_protocol_address>;
    
    public var description: String {
        return "(name: \(name), deviceId: \(deviceId) or \(UInt32(bitPattern: deviceId))";
    }
    
    public init(name: String, deviceId: Int32) {
        self.name = name;
        self.deviceId = deviceId;
        
        let rawPointer = malloc(MemoryLayout<signal_protocol_address>.size)!.assumingMemoryBound(to: signal_protocol_address.self);
        rawPointer.pointee.device_id = deviceId;
        let tmp = self.name.utf8CString;
        self.nameBytes = tmp.withUnsafeBytes { (inBuf) -> UnsafeMutablePointer<Int8> in
            let outBuf = malloc(tmp.count)!.assumingMemoryBound(to: Int8.self);
            memcpy(outBuf, inBuf.baseAddress!, tmp.count);
            return outBuf;
        }

        rawPointer.pointee.name = UnsafePointer(nameBytes);
        self.address = rawPointer;
    }
    
    deinit {
        free(address);
        free(nameBytes);
    }
    
    public convenience init?(from: UnsafePointer<signal_protocol_address>?) {
        guard let namePtr = from?.pointee.name, let name = String(validatingUTF8: namePtr), let deviceId = from?.pointee.device_id else {
            return nil;
        }
        
        self.init(name: name, deviceId: deviceId);
    }
        
    public convenience init?(from: UnsafePointer<signal_protocol_address?>?) {
        guard var addr = from?.pointee else {
            return nil;
        }
        self.init(from: &addr);
    }
}
