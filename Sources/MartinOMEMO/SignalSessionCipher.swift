//
// SignalSessionCipher.swift
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

open class SignalSessionCipher {
    
    fileprivate var cipher: OpaquePointer;
    fileprivate let context: SignalContext;
    fileprivate let address: SignalAddress;
    
    public init?(withAddress address: SignalAddress, andContext context: SignalContext) {
        var cipher: OpaquePointer?;
        self.address = address;
        guard session_cipher_create(&cipher, context.storage.storeContext, self.address.address, context.globalContext) >= 0 && cipher != nil else {
            return nil;
        }
        self.context = context;
        self.cipher = cipher!;
    }
    
    deinit {
        session_cipher_free(cipher);
    }
    
    func encrypt(data: Data) -> Result<Key,SignalError> {
        var message: OpaquePointer?;
        let error = data.withUnsafeBytes({ (bytes) -> SignalError? in
            return SignalError.from(code : session_cipher_encrypt(cipher, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), data.count, &message));
        })
        guard error == nil && message != nil else {
            return .failure(error ?? .unknown);
        }
        
        let serialized = ciphertext_message_get_serialized(message);
        let result = Data(bytes: signal_buffer_data(serialized), count: signal_buffer_len(serialized));
        
        defer {
            signal_type_unref(message);
        }
        return .success(Key(key: result, deviceId: address.deviceId, prekey: ciphertext_message_get_type(message) == CIPHERTEXT_PREKEY_TYPE));
    }
 
    func decrypt(key: Key) -> Result<Data, SignalError> {
        if key.prekey {
            return decryptPreKeyMessage(key: key);
        } else {
            return decryptSignalMessage(key: key);
        }
    }
    
    fileprivate func decryptPreKeyMessage(key: Key) -> Result<Data,SignalError> {
        let result = key.key.withUnsafeBytes({ (bytes) -> Result<OpaquePointer, SignalError> in
            var output: OpaquePointer?;
            var preKeySignalMessage: OpaquePointer?;
            
            var error = SignalError.from(code: pre_key_signal_message_deserialize(&preKeySignalMessage, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), key.key.count, self.context.globalContext));
            guard error == nil && preKeySignalMessage != nil else {
                return .failure(error ?? .unknown);
            }
            defer {
                signal_type_unref(preKeySignalMessage);
            }
            error = SignalError.from(code: session_cipher_decrypt_pre_key_signal_message(cipher, preKeySignalMessage, nil, &output));
            guard error == nil && output != nil else {
                return .failure(error ?? .unknown);
            }
            return .success(output!);
        })
        switch result {
        case .failure(let error):
            return .failure(error);
        case .success(let preKeySignalMessage):
            defer {
                signal_buffer_free(preKeySignalMessage);
            }
            return .success(Data(bytes: signal_buffer_data(preKeySignalMessage), count: signal_buffer_len(preKeySignalMessage)));
        }
    }
    
    fileprivate func decryptSignalMessage(key: Key) -> Result<Data, SignalError> {
        let result = key.key.withUnsafeBytes({ (bytes) -> Result<OpaquePointer,SignalError> in
            var output: OpaquePointer?;
            var signalMessage: OpaquePointer?;
            var error = SignalError.from(code: signal_message_deserialize(&signalMessage, bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), key.key.count, self.context.globalContext));
            guard error == nil && signalMessage != nil else {
                return .failure(error ?? .unknown);
            }
            defer {
                signal_type_unref(signalMessage);
            }
            error = SignalError.from(code: session_cipher_decrypt_signal_message(cipher, signalMessage, nil, &output));
            guard error == nil && output != nil else {
                return .failure(error ?? .unknown);
            }
            return .success(output!);
        });
        switch result {
        case .failure(let error):
            return .failure(error);
        case .success(let signalMessage):
            defer {
                signal_buffer_free(signalMessage);
            }
            return .success(Data(bytes: signal_buffer_data(signalMessage), count: signal_buffer_len(signalMessage)));
        }
    }
    
    open class Key {
        
        public let key: Data;
        public let deviceId: Int32;
        public let prekey: Bool;
        
        public init(key: Data, deviceId: Int32, prekey: Bool) {
            self.key = key;
            self.deviceId = deviceId;
            self.prekey = prekey;
        }
        
    }
    
}
