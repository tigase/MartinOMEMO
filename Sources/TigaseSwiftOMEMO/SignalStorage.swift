//
// SignalStorage.swift
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

open class SignalStorage {
    
    public let sessionStore: SignalSessionStoreProtocol;
    public let preKeyStore: SignalPreKeyStoreProtocol;
    public let signedPreKeyStore: SignalSignedPreKeyStoreProtocol;
    public let identityKeyStore: SignalIdentityKeyStoreProtocol;
    public let senderKeyStore: SignalSenderKeyStoreProtocol;
    
    fileprivate(set) var storeContext: OpaquePointer?;
    
    public init(sessionStore: SignalSessionStoreProtocol, preKeyStore: SignalPreKeyStoreProtocol, signedPreKeyStore: SignalSignedPreKeyStoreProtocol, identityKeyStore: SignalIdentityKeyStoreProtocol, senderKeyStore: SignalSenderKeyStoreProtocol) {
        self.sessionStore = sessionStore;
        self.preKeyStore = preKeyStore;
        self.signedPreKeyStore = signedPreKeyStore;
        self.identityKeyStore = identityKeyStore;
        self.senderKeyStore = senderKeyStore;
    }
    
    deinit {
        if storeContext != nil {
            signal_protocol_store_context_destroy(storeContext);
        }
        storeContext = nil;
    }
    
    open func setup(withContext context: SignalContext) {
        signal_protocol_store_context_create(&storeContext, context.globalContext);
        
        var sessionStoreCallbacks = signal_protocol_session_store();
        sessionStoreCallbacks.load_session_func = load_session_func;
        sessionStoreCallbacks.get_sub_device_sessions_func = get_sub_device_sessions_func;
        sessionStoreCallbacks.store_session_func = store_session_func;
        sessionStoreCallbacks.contains_session_func = contains_session_func;
        sessionStoreCallbacks.delete_session_func = delete_session_func;
        sessionStoreCallbacks.delete_all_sessions_func = delete_all_sessions_func;
        sessionStoreCallbacks.destroy_func = destroy_func;
        sessionStoreCallbacks.user_data = SignalContext.bridge(self.sessionStore as AnyObject);
        
        signal_protocol_store_context_set_session_store(storeContext, &sessionStoreCallbacks);
        
        var preKeyStoreCallbacks = signal_protocol_pre_key_store();
        preKeyStoreCallbacks.load_pre_key = load_pre_key;
        preKeyStoreCallbacks.store_pre_key = store_pre_key;
        preKeyStoreCallbacks.contains_pre_key = contains_pre_key;
        preKeyStoreCallbacks.remove_pre_key = remove_pre_key;
        preKeyStoreCallbacks.destroy_func = destroy_func;
        preKeyStoreCallbacks.user_data = SignalContext.bridge(self.preKeyStore as AnyObject);
        
        signal_protocol_store_context_set_pre_key_store(storeContext, &preKeyStoreCallbacks);

        var signedPreKeyStoreCallbacks = signal_protocol_signed_pre_key_store();
        signedPreKeyStoreCallbacks.load_signed_pre_key = load_signed_pre_key;
        signedPreKeyStoreCallbacks.store_signed_pre_key = store_signed_pre_key;
        signedPreKeyStoreCallbacks.contains_signed_pre_key = contains_signed_pre_key;
        signedPreKeyStoreCallbacks.remove_signed_pre_key = remove_signed_pre_key;
        signedPreKeyStoreCallbacks.destroy_func = destroy_func;
        signedPreKeyStoreCallbacks.user_data = SignalContext.bridge(self.signedPreKeyStore as AnyObject);
        
        signal_protocol_store_context_set_signed_pre_key_store(storeContext, &signedPreKeyStoreCallbacks);

        var identityKeyStoreCallbacks = signal_protocol_identity_key_store();
        identityKeyStoreCallbacks.get_identity_key_pair = get_identity_key_pair;
        identityKeyStoreCallbacks.get_local_registration_id = get_local_registration_id;
        identityKeyStoreCallbacks.save_identity = save_identity;
        identityKeyStoreCallbacks.is_trusted_identity = is_trusted_identity;
        identityKeyStoreCallbacks.destroy_func = destroy_func;
        identityKeyStoreCallbacks.user_data = SignalContext.bridge(self.identityKeyStore as AnyObject);
        
        signal_protocol_store_context_set_identity_key_store(storeContext, &identityKeyStoreCallbacks);
        
        var senderKeyStoreCallbacks = signal_protocol_sender_key_store();
        senderKeyStoreCallbacks.store_sender_key = store_sender_key;
        senderKeyStoreCallbacks.load_sender_key = load_sender_key;
        senderKeyStoreCallbacks.destroy_func = destroy_func;
        identityKeyStoreCallbacks.user_data = SignalContext.bridge(self.senderKeyStore as AnyObject);
        
        signal_protocol_store_context_set_sender_key_store(storeContext, &senderKeyStoreCallbacks);
    }
    
    open func regenerateKeys(wipe: Bool = false) -> Bool {
        return false;
    };
}

public protocol SignalSessionStoreProtocol: class {

    func sessionRecord(forAddress address: SignalAddress) -> Data?;
 
    func allDevices(for: String, activeAndTrusted: Bool) -> [Int32];
    
    func storeSessionRecord(_ data: Data, forAddress: SignalAddress) -> Bool;
    
    func containsSessionRecord(forAddress: SignalAddress) -> Bool;
    
    func deleteSessionRecord(forAddress: SignalAddress) -> Bool;
    
    func deleteAllSessions(for: String) -> Bool;
}

public protocol SignalPreKeyStoreProtocol: class {
    
    func currentPreKeyId() -> UInt32;
    
    func loadPreKey(withId: UInt32) -> Data?;
    
    func storePreKey(_ data: Data, withId: UInt32) -> Bool;
    
    func containsPreKey(withId: UInt32) -> Bool;
    
    func deletePreKey(withId: UInt32) -> Bool;
}

public protocol SignalSignedPreKeyStoreProtocol: class {

    func countSignedPreKeys() -> Int;
    
    func loadSignedPreKey(withId: UInt32) -> Data?;
    
    func storeSignedPreKey(_ data: Data, withId: UInt32) -> Bool;
    
    func containsSignedPreKey(withId: UInt32) -> Bool;
    
    func deleteSignedPreKey(withId: UInt32) -> Bool;
}

public protocol SignalIdentityKeyStoreProtocol: class {
    
    func keyPair() -> SignalIdentityKeyPairProtocol?;
    func localRegistrationId() -> UInt32;
    
    func save(identity: SignalAddress, key: SignalIdentityKeyProtocol?) -> Bool;
    func isTrusted(identity: SignalAddress, key: SignalIdentityKeyProtocol?) -> Bool;
    func save(identity: SignalAddress, publicKeyData: Data?) -> Bool;
    func isTrusted(identity: SignalAddress, publicKeyData: Data?) -> Bool;
    
    func setStatus(_ status: IdentityStatus, forIdentity: SignalAddress) -> Bool;
    func setStatus(active: Bool, forIdentity: SignalAddress) -> Bool;

    func identities(forName: String) -> [Identity];
    func identityFingerprint(forAddress address: SignalAddress) -> String?
}

public protocol SignalIdentityKeyProtocol: class {
    var publicKeyPointer: OpaquePointer { get }
    var publicKey: Data? { get }
    
    func serialized() -> Data;
}

public protocol SignalIdentityKeyPairProtocol: SignalIdentityKeyProtocol {
    var keyPairPointer: OpaquePointer? { get }
    var keyPair: Data? { get }
    var privateKeyPointer: OpaquePointer { get }
    var privateKey: Data? { get }
}

public protocol SignalSenderKeyStoreProtocol: class {
    
    func storeSenderKey(_ key: Data, address: SignalAddress?, groupId: String?) -> Bool;
    func loadSenderKey(forAddress: SignalAddress?, groupId: String?) -> Data?;
}

fileprivate func load_session_func(record: UnsafeMutablePointer<OpaquePointer?>?, userRecord: UnsafeMutablePointer<OpaquePointer?>?, address: UnsafePointer<signal_protocol_address>?, userData: UnsafeMutableRawPointer?) -> CInt {
    let sessionStore: SignalSessionStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalSessionStoreProtocol;
    guard let addr = SignalAddress(from: address) else {
        return -1;
    }
    
    guard let data = sessionStore.sessionRecord(forAddress: addr) else {
        return 0;
    }
    
    data.withUnsafeBytes({ (ptr: UnsafeRawBufferPointer) -> Void in
        record?.initialize(to: signal_buffer_create(ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), data.count));
    })
    return 1;
}

fileprivate func get_sub_device_sessions_func(sessions: UnsafeMutablePointer<OpaquePointer?>?, name namePtr: UnsafePointer<Int8>?, nameLen: Int, userData: UnsafeMutableRawPointer?) -> CInt {
    let sessionStore: SignalSessionStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalSessionStoreProtocol;
    guard let name = String(validatingUTF8: namePtr!) else {
        return -1;
    }
    let devices = sessionStore.allDevices(for: name, activeAndTrusted: false);
    guard let list = signal_int_list_alloc() else {
        return -1;
    }
    
    devices.forEach { device in
        signal_int_list_push_back(list, device);
    }
    return CInt(devices.count);
}

fileprivate func store_session_func(address: UnsafePointer<signal_protocol_address>?, record: UnsafeMutablePointer<UInt8>?, recordLen: Int, userRecord: UnsafeMutablePointer<UInt8>?, userRecordLen: Int, userData: UnsafeMutableRawPointer?) -> CInt {
    let sessionStore: SignalSessionStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalSessionStoreProtocol;
    guard let addr = SignalAddress(from: address) else {
        return -1;
    }
    let data = Data(bytes: record!, count: recordLen);
    return sessionStore.storeSessionRecord(data, forAddress: addr) ? 0 : -1;
}

fileprivate func contains_session_func(address: UnsafePointer<signal_protocol_address>?, userData: UnsafeMutableRawPointer?) -> CInt {
    let sessionStore: SignalSessionStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalSessionStoreProtocol;
    guard let addr = SignalAddress(from: address) else {
        return -1;
    }
    return sessionStore.containsSessionRecord(forAddress: addr) ? 1 : 0;
}

fileprivate func delete_session_func(address: UnsafePointer<signal_protocol_address>?, userData: UnsafeMutableRawPointer?) -> CInt {
    let sessionStore: SignalSessionStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalSessionStoreProtocol;
    guard let addr = SignalAddress(from: address) else {
        return -1;
    }
    return sessionStore.deleteSessionRecord(forAddress: addr) ? 1 : 0;
}

fileprivate func delete_all_sessions_func(name namePtr: UnsafePointer<Int8>?, nameLen: Int, userData: UnsafeMutableRawPointer?) -> CInt {
    let sessionStore: SignalSessionStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalSessionStoreProtocol;
    guard let name = String(validatingUTF8: namePtr!) else {
        return -1;
    }
    
    return sessionStore.deleteAllSessions(for: name) ? 1 : 0;
}

fileprivate func destroy_func(userData: UnsafeMutableRawPointer?) {
    
}

fileprivate func load_pre_key(record: UnsafeMutablePointer<OpaquePointer?>?, preKeyId: UInt32, userData: UnsafeMutableRawPointer?) -> CInt {
    let preKeyStore: SignalPreKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalPreKeyStoreProtocol;
    guard let preKey = preKeyStore.loadPreKey(withId: preKeyId) else {
        return SG_ERR_INVALID_KEY_ID;
    }
    
    preKey.withUnsafeBytes({ (bytes: UnsafeRawBufferPointer)->Void in
        let buffer = signal_buffer_create(bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), preKey.count);
        record?.initialize(to: buffer);
    })
    return SG_SUCCESS;
}

fileprivate func store_pre_key(preKeyId: UInt32, record: UnsafeMutablePointer<UInt8>?, recordLen: Int, userData: UnsafeMutableRawPointer?) -> CInt {
    let preKeyStore: SignalPreKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalPreKeyStoreProtocol;
     let data = Data(bytes: record!, count: recordLen);
    return preKeyStore.storePreKey(data, withId: preKeyId) ? 0 : -1;
}

fileprivate func contains_pre_key(preKeyId: UInt32, userData: UnsafeMutableRawPointer?) -> CInt {
    let preKeyStore: SignalPreKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalPreKeyStoreProtocol;
    return preKeyStore.containsPreKey(withId: preKeyId) ? 1 : 0;
}

fileprivate func remove_pre_key(preKeyId: UInt32, userData: UnsafeMutableRawPointer?) -> CInt {
    let preKeyStore: SignalPreKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalPreKeyStoreProtocol;
    return preKeyStore.deletePreKey(withId: preKeyId) ? 0 : -1;
}

fileprivate func load_signed_pre_key(record: UnsafeMutablePointer<OpaquePointer?>?, signedPreKeyId: UInt32, userData: UnsafeMutableRawPointer?) -> CInt {
    let signedPreKeyStore: SignalSignedPreKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalSignedPreKeyStoreProtocol;
    guard let preKey = signedPreKeyStore.loadSignedPreKey(withId: signedPreKeyId) else {
        return SG_ERR_INVALID_KEY_ID;
    }
    
    preKey.withUnsafeBytes({ (bytes: UnsafeRawBufferPointer)->Void in
        let buffer = signal_buffer_create(bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), preKey.count);
        record?.initialize(to: buffer);
    })
    return SG_SUCCESS;
}

fileprivate func store_signed_pre_key(signedPreKeyId: UInt32, record: UnsafeMutablePointer<UInt8>?, recordLen: Int, userData: UnsafeMutableRawPointer?) -> CInt {
    let signedPreKeyStore: SignalSignedPreKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalSignedPreKeyStoreProtocol;
    let data = Data(bytes: record!, count: recordLen);
    return signedPreKeyStore.storeSignedPreKey(data, withId: signedPreKeyId) ? 0 : -1;
}

fileprivate func contains_signed_pre_key(signedPreKeyId: UInt32, userData: UnsafeMutableRawPointer?) -> CInt {
    let signedPreKeyStore: SignalSignedPreKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalSignedPreKeyStoreProtocol;
    return signedPreKeyStore.containsSignedPreKey(withId: signedPreKeyId) ? 1 : 0;
}

fileprivate func remove_signed_pre_key(signedPreKeyId: UInt32, userData: UnsafeMutableRawPointer?) -> CInt {
    let signedPreKeyStore: SignalSignedPreKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalSignedPreKeyStoreProtocol;
    return signedPreKeyStore.deleteSignedPreKey(withId: signedPreKeyId) ? 0 : -1;
}

fileprivate func get_identity_key_pair(publicData: UnsafeMutablePointer<OpaquePointer?>?, privateData: UnsafeMutablePointer<OpaquePointer?>?, userData: UnsafeMutableRawPointer?) -> CInt {
    let identityKeyStore: SignalIdentityKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalIdentityKeyStoreProtocol;
    guard let keyPair = identityKeyStore.keyPair() else {
        return -1;
    }
    
    if let publicKey = keyPair.publicKey {
        publicKey.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Void in
            let buffer = signal_buffer_create(bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), publicKey.count);
            publicData?.initialize(to: buffer);
        }
    }

    if let privateKey = keyPair.privateKey {
        privateKey.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Void in
            let buffer = signal_buffer_create(bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), privateKey.count);
            privateData?.initialize(to: buffer);
        }
    }
    
    return 0;
}

fileprivate func get_local_registration_id(userData: UnsafeMutableRawPointer?, registrationId: UnsafeMutablePointer<UInt32>?) -> CInt {
    let identityKeyStore: SignalIdentityKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalIdentityKeyStoreProtocol;
    let regId = identityKeyStore.localRegistrationId();
    if regId > 0 {
        registrationId?.initialize(to: regId);
        return 0;
    } else {
        return -1;
    }
}

fileprivate func save_identity(address: UnsafePointer<signal_protocol_address>?, keyData: UnsafeMutablePointer<UInt8>?, keyLen: Int, userData: UnsafeMutableRawPointer?) -> CInt {
    let identityKeyStore: SignalIdentityKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalIdentityKeyStoreProtocol;
    guard let addr = SignalAddress(from: address) else {
        return -1;
    }
    return identityKeyStore.save(identity: addr, publicKeyData: keyData == nil ? nil : Data(bytes: keyData!, count: keyLen)) ? 0 : -1;
}

fileprivate func is_trusted_identity(address: UnsafePointer<signal_protocol_address>?, keyData: UnsafeMutablePointer<UInt8>?, keyLen: Int, userData: UnsafeMutableRawPointer?) -> CInt {
    let identityKeyStore: SignalIdentityKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalIdentityKeyStoreProtocol;
    guard let addr = SignalAddress(from: address) else {
        return -1;
    }
    return identityKeyStore.isTrusted(identity: addr, publicKeyData: Data(bytes: keyData!, count: keyLen)) ? 1 : 0;
}

fileprivate func store_sender_key(senderKeyName: UnsafePointer<signal_protocol_sender_key_name>?, record: UnsafeMutablePointer<UInt8>?, recordLen: Int, userRecord: UnsafeMutablePointer<UInt8>?, userRecordLen: Int, userData: UnsafeMutableRawPointer?) -> CInt {
    let senderKeyStore: SignalSenderKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalSenderKeyStoreProtocol;
    
    var sender = senderKeyName?.pointee.sender;
    let groupId = senderKeyName?.pointee.group_id;
    let group = groupId != nil ? String(validatingUTF8: groupId!) : nil;
    let addr = SignalAddress(from: &sender)
    let key = Data(bytes: record!, count: recordLen);
    
    return senderKeyStore.storeSenderKey(key, address: addr, groupId: group) ? 0 : -1;
}

fileprivate func load_sender_key(record: UnsafeMutablePointer<OpaquePointer?>?, userRecord: UnsafeMutablePointer<OpaquePointer?>?, senderKeyName: UnsafePointer<signal_protocol_sender_key_name>?, userData: UnsafeMutableRawPointer?) -> CInt {
    let senderKeyStore: SignalSenderKeyStoreProtocol = SignalContext.bridge(fromPointer: userData!) as! SignalSenderKeyStoreProtocol;

    var sender = senderKeyName?.pointee.sender;
    let groupId = senderKeyName?.pointee.group_id;
    let group = groupId != nil ? String(validatingUTF8: groupId!) : nil;
    let addr = SignalAddress(from: &sender)

    if let key = senderKeyStore.loadSenderKey(forAddress: addr, groupId: group) {
        key.withUnsafeBytes({ (bytes: UnsafeRawBufferPointer) -> Void in
            let buffer = signal_buffer_create(bytes.baseAddress!.assumingMemoryBound(to: UInt8.self), key.count);
            record?.initialize(to: buffer);
        });
        return 1;
    } else {
        return 0;
    }
}
