//
// SignalIdentityKey.swift
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

open class SignalIdentityKey: SignalIdentityKeyProtocol {

    public static func publicKey(from publicKey: Data) -> OpaquePointer? {
        return publicKey.withUnsafeBytes({ (bytes) -> OpaquePointer? in
            var tmp: OpaquePointer?;
            guard curve_decode_point(&tmp, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), publicKey.count, nil) >= 0 else {
                return nil;
            }
            return tmp;
        });
    }
    
    public static func serialize(publicKeyPointer: OpaquePointer) -> Data? {
        var buffer: OpaquePointer?;
        guard ec_public_key_serialize(&buffer, publicKeyPointer) == 0 && buffer != nil else {
            return nil;
        }
        
        defer {
            signal_buffer_bzero_free(buffer);
        }
        return Data(bytes: signal_buffer_data(buffer), count: signal_buffer_len(buffer));
    }
    
    public let publicKeyPointer: OpaquePointer;

    public var publicKeyData: Data? {
        return SignalIdentityKey.serialize(publicKeyPointer: publicKeyPointer);
    }
    
    public convenience init?(data: Data?) {
        guard let data = data, let pointer = SignalIdentityKey.publicKey(from: data) else {
            return nil;
        }
        
        self.init(publicKeyPointer: pointer);
    }
    
    public init(publicKeyPointer: OpaquePointer) {
        self.publicKeyPointer = publicKeyPointer;
        signal_type_ref(self.publicKeyPointer);
    }
    
    deinit {
        signal_type_unref(publicKeyPointer);
    }
    
    public func serialized() -> Data {
        return publicKeyData!;
    }
    
}
