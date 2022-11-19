//
// SignalIdentityKeyPair.swift
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

open class SignalIdentityKeyPair: SignalIdentityKeyProtocol, SignalIdentityKeyPairProtocol {

    public let keyPairPointer: OpaquePointer;

    public var publicKeyPointer: OpaquePointer {
        return ratchet_identity_key_pair_get_public(keyPairPointer);
    }
    
    public var publicKeyData: Data? {
        return SignalIdentityKey.serialize(publicKeyPointer: publicKeyPointer);
    }
    
    public var privateKeyPointer: OpaquePointer {
        return ratchet_identity_key_pair_get_private(keyPairPointer);
    }

    public var privateKeyData: Data? {
        var buffer: OpaquePointer?;
        guard ec_private_key_serialize(&buffer, privateKeyPointer) == 0 && buffer != nil else {
            return nil;
        }
        defer {
            signal_buffer_bzero_free(buffer);
        }
        return Data(bytes: signal_buffer_data(buffer), count: signal_buffer_len(buffer));
    }
    
    public var keyPairData: Data? {
        var buffer: OpaquePointer?;
        guard ratchet_identity_key_pair_serialize(&buffer, keyPairPointer) == 0 && buffer != nil else {
            return nil;
        }
        defer {
            signal_buffer_bzero_free(buffer);
        }
        return Data(bytes: signal_buffer_data(buffer), count: signal_buffer_len(buffer));
    }
    
    public convenience init?(publicKey: Data?, privateKey: Data?) {
        guard publicKey != nil && privateKey != nil else {
            return nil;
        }
        
        guard let privateKeyPointer = privateKey!.withUnsafeBytes({ (bytes) -> OpaquePointer? in
            var tmp: OpaquePointer?;
            guard curve_decode_private_point(&tmp, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), privateKey!.count, nil) >= 0 else {
                return nil;
            }
            return tmp;
        }) else {
            return nil;
        }
        
        guard let publicKeyPointer = publicKey!.withUnsafeBytes({ (bytes) -> OpaquePointer? in
            var tmp: OpaquePointer?;
            guard curve_decode_point(&tmp, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), publicKey!.count, nil) >= 0 else {
                return nil;
            }
            return tmp;
        }) else {
            return nil;
        }

        var pointer: OpaquePointer?;
        ec_key_pair_create(&pointer, publicKeyPointer, privateKeyPointer);
        guard let pointer = pointer else {
            return nil;
        }
        
        self.init(withKeyPairPointer: pointer);
    }
    
    public init(withKeyPairPointer keyPairPointer: OpaquePointer) {
        signal_type_ref(keyPairPointer);
        self.keyPairPointer = keyPairPointer;
    }
    
    public convenience init?(fromKeyPairData data: Data) {
        guard let keyPair = data.withUnsafeBytes({ (bytes) -> OpaquePointer? in
            var tmp: OpaquePointer?;
            guard ratchet_identity_key_pair_deserialize(&tmp, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), data.count, nil) >= 0 && tmp != nil else {
                return nil;
            }
            return tmp;
        }) else {
            return nil;
        }
        self.init(withKeyPairPointer: keyPair);
    }
    
    deinit {
        signal_type_unref(keyPairPointer);
    }
    
    public static func generateKeyPair(context: SignalContext) -> SignalIdentityKeyPair? {
        var keyPair: OpaquePointer? = nil;
        let result = signal_protocol_key_helper_generate_identity_key_pair(&keyPair, context.globalContext);
        guard result >= 0, let keyPair = keyPair else {
            return nil;
        }
        return SignalIdentityKeyPair(withKeyPairPointer: keyPair);
    }
 
    public func serialized() -> Data {
        return keyPairData!;
    }
}
