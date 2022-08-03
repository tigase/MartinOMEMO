//
// SignalContext.swift
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

open class SignalContext {
    
    public fileprivate(set) var globalContext: OpaquePointer?;
    fileprivate let provider: SignalCryptoProvider = SignalCryptoProvider();
    fileprivate let lock: NSRecursiveLock = NSRecursiveLock();
    let storage: SignalStorage;
    
    public init?(withStorage: SignalStorage) {
        self.storage = withStorage;

        guard signal_context_create(&globalContext, SignalContext.bridge(self)) == 0 else {
            return nil;
        }

        var provider = self.provider.provider;
        signal_context_set_crypto_provider(globalContext, &provider)
        
        signal_context_set_locking_functions(globalContext, signalLock, signalUnlock)
        signal_context_set_log_function(globalContext, signalLog);

        self.storage.setup(withContext: self);
    }
    
    open func generateRegistrationId() -> UInt32 {
        var regId: UInt32 = 0;
        let res = signal_protocol_key_helper_generate_registration_id(&regId, 1, self.globalContext!);
        guard res >= 0 else {
            return 0;
        }
        return regId;
    }
    
    open func generatePreKeys(withStartingPreKeyId preKeyId: UInt32, count: UInt32) -> [SignalPreKey] {
        var head: OpaquePointer? = nil;
        guard signal_protocol_key_helper_generate_pre_keys(&head, preKeyId, count, globalContext) >= 0 && head != nil else {
            return [];
        }
        var keys: [SignalPreKey] = [];
        while (head != nil) {
            if let pre_key = signal_protocol_key_helper_key_list_element(head) {
                keys.append(SignalPreKey(fromPreKey: pre_key));
            }
            head = signal_protocol_key_helper_key_list_next(head);
        }
        return keys;
    }
    
    open func generateSignedPreKey(withIdentity identity: SignalIdentityKeyPairProtocol, signedPreKeyId: UInt32, timestamp: Date = Date()) -> SignalSignedPreKey? {
        guard let keyPair = identity.keyPairPointer else {
            return nil;
        }
        
        var signed_pre_key: OpaquePointer?;
        guard signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key, keyPair, signedPreKeyId, UInt64(timestamp.timeIntervalSince1970) * 1000, globalContext) >= 0 && signed_pre_key != nil else {
            return nil;
        }
        
        return SignalSignedPreKey(fromSignedPreKey: signed_pre_key!);
    }
    
    static func bridge<T : AnyObject>(_ obj : T) -> UnsafeMutableRawPointer {
        return Unmanaged.passUnretained(obj).toOpaque();
    }
    
    static func bridge<T : AnyObject>(_ ptr : UnsafeMutableRawPointer) -> T {
        return Unmanaged<T>.fromOpaque(ptr).takeUnretainedValue();
    }

    static func bridge(fromPointer ptr : UnsafeMutableRawPointer) -> AnyObject {
        return Unmanaged.fromOpaque(ptr).takeUnretainedValue();
    }

}

fileprivate func signalLock(_ userData: UnsafeMutableRawPointer?) {
    let ctx: SignalContext = SignalContext.bridge(userData!);
    ctx.lock.lock();
}

fileprivate func signalUnlock(_ userData: UnsafeMutableRawPointer?) {
    let ctx: SignalContext = SignalContext.bridge(userData!);
    ctx.lock.unlock();
}

fileprivate func signalLog(level: CInt, message: UnsafePointer<Int8>?, len: Int, userData: UnsafeMutableRawPointer?) {
    print("SignalProtocol:", level, String(validatingUTF8: message!) as Any);
}

open class SignalSignedPreKey {

    fileprivate let signedPreKey: OpaquePointer;
    
    public var preKeyId: UInt32 {
        return session_signed_pre_key_get_id(signedPreKey);
    }
    
    public var timestamp: Date {
        return Date(timeIntervalSince1970: TimeInterval(session_signed_pre_key_get_timestamp(signedPreKey) / 1000));
    }
    
    public var signature: Data {
        let sigBytes = session_signed_pre_key_get_signature(signedPreKey);
        let sigLen = session_signed_pre_key_get_signature_len(signedPreKey);
        return Data(bytes: sigBytes!, count: sigLen);
    }
    
    public var serializedData: Data? {
        var buf: OpaquePointer?;
        guard session_signed_pre_key_serialize(&buf, signedPreKey) == 0 && buf != nil else {
            return nil;
        }
        
        defer {
            signal_buffer_free(buf);
        }
        return Data(bytes: signal_buffer_data(buf), count: signal_buffer_len(buf));
    }
    
    public var publicKeyData: Data? {
        guard let keyPair = session_signed_pre_key_get_key_pair(signedPreKey) else {
            return nil;
        }
        guard let publicKey = ec_key_pair_get_public(keyPair) else {
            return nil;
        }
        var buf: OpaquePointer?;
        guard ec_public_key_serialize(&buf, publicKey) >= 0 && buf != nil else {
            return nil;
        }
        
        defer {
            signal_buffer_free(buf);
        }
        return Data(bytes: signal_buffer_data(buf), count: signal_buffer_len(buf));
    }
    
    public init(fromSignedPreKey: OpaquePointer) {
        self.signedPreKey = fromSignedPreKey;
        signal_type_ref(signedPreKey);
    }

    public convenience init?(fromSerializedData: Data) {
        guard let preKey: OpaquePointer = fromSerializedData.withUnsafeBytes({ (bytes) -> OpaquePointer? in
            var tmp: OpaquePointer?;
            guard session_signed_pre_key_deserialize(&tmp, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), fromSerializedData.count, nil) >= 0 else {
                return nil;
            }
            return tmp;
        }) else {
            return nil;
        }
        self.init(fromSignedPreKey: preKey);
    }
    
    deinit {
        signal_type_unref(signedPreKey);
    }
}

open class SignalPreKey {
    
    fileprivate let preKey: OpaquePointer;

    public var preKeyId: UInt32 {
        return session_pre_key_get_id(preKey);
    }
    
    public var serializedData: Data? {
        var buf: OpaquePointer?;
        guard session_pre_key_serialize(&buf, preKey) == 0 && buf != nil else {
            return nil;
        }
        
        defer {
            signal_buffer_free(buf);
        }
        return Data(bytes: signal_buffer_data(buf), count: signal_buffer_len(buf));
    }
    
    public var serializedPublicKey: Data? {
        let keyPair = session_signed_pre_key_get_key_pair(preKey);
        var buf: OpaquePointer?;
        guard ec_public_key_serialize(&buf, ec_key_pair_get_public(keyPair)) >= 0 else {
            return nil;
        }
        defer {
            signal_buffer_free(buf);
        }
        return Data(bytes: signal_buffer_data(buf), count: signal_buffer_len(buf));
    }
    
    public init(fromPreKey: OpaquePointer) {
        self.preKey = fromPreKey;
        signal_type_ref(self.preKey);
    }
    
    public convenience init?(fromSerializedData: Data) {
        guard let preKey: OpaquePointer = fromSerializedData.withUnsafeBytes({ (bytes) -> OpaquePointer? in
            var tmp: OpaquePointer?;
            guard session_pre_key_deserialize(&tmp, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), fromSerializedData.count, nil) >= 0 else {
                return nil;
            }
            return tmp;
        }) else {
            return nil;
        }
        self.init(fromPreKey: preKey);
    }
    
    deinit {
        signal_type_unref(preKey);
    }
    
}
