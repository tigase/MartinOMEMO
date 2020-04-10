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

open class SignalIdentityKeyPair: SignalIdentityKey, SignalIdentityKeyPairProtocol {
    
    public let privateKeyPointer: OpaquePointer;
    
    fileprivate var _keyPairPointer: OpaquePointer?;
    public var keyPairPointer: OpaquePointer? {
        if _keyPairPointer == nil {
            ec_key_pair_create(&_keyPairPointer, publicKeyPointer, privateKeyPointer);
        }
        return _keyPairPointer;
    }

    fileprivate var _privateKey: Data?;
    public var privateKey: Data? {
        if _privateKey == nil {
            var buffer: OpaquePointer?;
            guard ec_private_key_serialize(&buffer, privateKeyPointer) == 0 && buffer != nil else {
                return nil;
            }
            _privateKey = Data(bytes: signal_buffer_data(buffer), count: signal_buffer_len(buffer));
            signal_buffer_bzero_free(buffer);
        }
        return _privateKey;
    }
    
    public var keyPair: Data? {
        guard let keyPairPointer = self.keyPairPointer else {
            return nil;
        }
        var buffer: OpaquePointer?;
        guard ratchet_identity_key_pair_serialize(&buffer, keyPairPointer) == 0 && buffer != nil else {
            return nil;
        }
        defer {
            signal_buffer_bzero_free(buffer);
        }
        return Data(bytes: signal_buffer_data(buffer), count: signal_buffer_len(buffer));
    }
    
    public init?(publicKey: Data?, privateKey: Data?) {
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

        self.privateKeyPointer = privateKeyPointer;
        signal_type_ref(self.privateKeyPointer);
        super.init(publicKeyPointer: publicKeyPointer);
    }
    
    public init(withKeyPair keyPair: OpaquePointer) {
        privateKeyPointer = ratchet_identity_key_pair_get_private(keyPair);
        signal_type_ref(self.privateKeyPointer);
        super.init(publicKeyPointer: ratchet_identity_key_pair_get_public(keyPair));
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
        self.init(withKeyPair: keyPair);
    }
    
    deinit {
        signal_type_unref(privateKeyPointer);
        if keyPairPointer != nil {
            signal_type_unref(keyPairPointer);
            _keyPairPointer = nil;
        }
    }
    
    public static func generateKeyPair(context: SignalContext) -> SignalIdentityKeyPair? {
        var keyPair: OpaquePointer? = nil;
        let result = signal_protocol_key_helper_generate_identity_key_pair(&keyPair, context.globalContext);
        guard result >= 0 && keyPair != nil else {
            return nil;
        }
        return SignalIdentityKeyPair(withKeyPair: keyPair!);
    }
    
    override open func serialized() -> Data {
        return keyPair!;
    }
}
