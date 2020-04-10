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
    
    public let publicKeyPointer: OpaquePointer;

    fileprivate var _publicKey: Data?;
    public var publicKey: Data? {
        if _publicKey == nil {
            var buffer: OpaquePointer?;
            guard ec_public_key_serialize(&buffer, publicKeyPointer) == 0 && buffer != nil else {
                return nil;
            }
            _publicKey = Data(bytes: signal_buffer_data(buffer), count: signal_buffer_len(buffer));
            signal_buffer_bzero_free(buffer);
        }
        return _publicKey;
    }
    
    public convenience init?(publicKey: Data?) {
        guard publicKey != nil else {
            return nil;
        }
        guard let publicKeyPointer = SignalIdentityKey.publicKey(from: publicKey!) else {
            return nil;
        }
        
        self.init(publicKeyPointer: publicKeyPointer);
    }
    
    public init(publicKeyPointer: OpaquePointer) {
        self.publicKeyPointer = publicKeyPointer;
        signal_type_ref(self.publicKeyPointer);
    }
    
    deinit {
        signal_type_unref(publicKeyPointer);
    }
    
    open func serialized() -> Data {
        return publicKey!;
    }
}
