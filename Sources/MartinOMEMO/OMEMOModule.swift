//
// OMEMOModule.swift
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
import Martin
import libsignal
import Combine
import CryptoKit
import os

extension XmppModuleIdentifier {
    public static var omemo: XmppModuleIdentifier<OMEMOModule> {
        return OMEMOModule.IDENTIFIER;
    }
}

struct KeyDecryptionResult {
    let result: Result<Data,SignalError>;
    let address: SignalAddress;
    let isPrekey: Bool;
    
    var isSuccess: Bool {
        switch result {
        case .success(_):
            return true;
        case .failure(_):
            return false;
        }
    }
}

open class OMEMOModule: AbstractPEPModule, XmppModule, Resetable, @unchecked Sendable {
    
    public static let ID = "omemo";
    public static let IDENTIFIER = XmppModuleIdentifier<OMEMOModule>();
    public static let XMLNS = "eu.siacs.conversations.axolotl";
    public static let DEVICES_LIST_NODE = "eu.siacs.conversations.axolotl.devicelist";
    
    public let id: String = ID;

    private let logger = Logger(subsystem: "TigaseSwiftOMEMO", category: "OMEMOModule")
    
    // Default body to set for OMEMO encrypted messages
    open var defaultBody: String? = "I sent you an OMEMO encrypted message but your client doesn’t seem to support that.";
    
    public override var isPepAvailable: Bool {
        didSet {
            if isPepAvailable {
                Task {
                    try await publishDeviceBundleIfNeeded();
                    await publishDeviceIdIfNeeded();
                }
            }
        }
    }

    public let criteria = Criteria.empty();

    public let features: [String] = [OMEMOModule.DEVICES_LIST_NODE + "+notify"];
    
    public let signalContext: SignalContext;
    public let storage: SignalStorage;
    private let state = OMEMOState();

    @Published
    public private(set) var isReady: Bool = false;
    
    public let activeDevicesPublisher = PassthroughSubject<AvailabilityChanged,Never>();
    
    public func isAvailable(for jid: BareJID) async -> Bool {
        return await state.isAvailable(for: jid) || !self.storage.sessionStore.allDevices(for: jid.description, activeAndTrusted: true).isEmpty;
    }
        
    public init(signalContext: SignalContext, signalStorage: SignalStorage) {
        self.signalContext = signalContext;
        self.storage = signalStorage;
        super.init();
    }
    
    public func reset(scopes: Set<ResetableScope>) {
        if scopes.contains(.session) {
            self.isReady = false;
            Task {
                await self.state.reset();
            }
        }
    }
    
    public func regenerateKeys(wipe: Bool = false) -> Bool {
        let regenerated = self.storage.regenerateKeys(wipe: wipe);
        if regenerated && isPepAvailable {
            Task {
                try await self.publishDeviceBundle(currentBundle: nil)
                await self.publishDeviceIdIfNeeded()
            }
        }
        return regenerated;
    }
    
    public func devices(for jid: BareJID) async -> [Int32]? {
        return await state.devices(for: jid);
    }
    
    public func devices(for jid: BareJID, completionHandler: @escaping ([Int32]?)->Void) {
        Task {
            completionHandler(await devices(for: jid));
        }
    }
    
    public func process(stanza: Stanza) throws {
        throw XMPPError(condition: .feature_not_implemented);
    }
    
    public func decrypt(message: Message, serverMsgId: String? = nil) throws -> DecryptionResult {
        guard let from = message.from?.bareJid else {
            throw SignalError.invalidArgument;
        }
        return try self.decrypt(message: message, from: from, serverMsgId: serverMsgId)
    }
    
    public struct DecryptedKey {
        let data: Data;
        let address: SignalAddress;
        let isPreKey: Bool
    }
    
    public func decryptKey(possibleKeys: [SignalSessionCipher.Key], senderAddress: SignalAddress, context: Context, storage: SignalStorage, healFn: @escaping ()->Void) throws -> DecryptedKey? {
        guard !possibleKeys.isEmpty else {
            return nil;
        }
        
        let cipher = try SignalSessionCipher(withAddress: senderAddress, andContext: self.signalContext);
        for key in possibleKeys {
            do {
                let decodedKey = try cipher.decrypt(key: key);
                return .init(data: decodedKey, address: senderAddress, isPreKey: key.prekey);
            } catch {
                logger.error("failed to decrypt key from: \(senderAddress): \(error)")
                switch error as? SignalError {
                case .invalidMessage, .noSession, .invalidKeyId:
                    healFn();
                default:
                    break;
                }
                if possibleKeys.last == key {
                    throw error;
                }
            }
        }
        
        // FIXME: this should not happen!!
        fatalError("Didn't throw and did not return value!")
    }
        
    public func decrypt(message: Message, from: BareJID, serverMsgId: String? = nil) throws -> DecryptionResult {
        guard let context = context, let storage = signalContext.storage else {
            throw SignalError.unknown;
        }

        guard let encryptedEl = message.firstChild(name: "encrypted", xmlns: OMEMOModule.XMLNS) else {
            throw SignalError.notEncrypted;
        }
        
        guard let headerEl = encryptedEl.firstChild(name: "header"), let sid = UInt32(headerEl.attribute("sid") ?? "") else {
            throw SignalError.invalidArgument;
        }
        
        let localDeviceIdStr = String(storage.identityKeyStore.localRegistrationId());
                
        let possibleKeys = headerEl.filterChildren(where: { (el) -> Bool in
            return el.name == "key" && el.attribute("rid") == localDeviceIdStr;
        }).compactMap({ keyEl -> SignalSessionCipher.Key? in
            let prekey = "true" == keyEl.attribute("prekey") || keyEl.attribute("prekey") == "1";
            guard let keyElValue = keyEl.value, let key = Data(base64Encoded: keyElValue) else {
                return nil;
            }
            return SignalSessionCipher.Key(key: key, deviceId: Int32(bitPattern: sid), prekey: prekey);
        })
        
        let senderAddress = SignalAddress(name: from.description, deviceId: Int32(bitPattern: sid));
        let healFn = {
            if serverMsgId != nil {
                Task {
                    let isPostponed = await self.state.postponedHealing(for: message.type == .groupchat ? message.from?.bareJid : nil, address: senderAddress)
                    if !isPostponed {
                        await self.buildSession(forAddress: senderAddress);
                        self.completeSession(forAddress: senderAddress);
                    }
                }
            }
        }
        
        guard let decryptedKey = try decryptKey(possibleKeys: possibleKeys, senderAddress: senderAddress, context: context, storage: storage, healFn: healFn) else {
            guard context.userBareJid != from || sid != storage.identityKeyStore.localRegistrationId() else {
                throw SignalError.duplicateMessage;
            }
            guard encryptedEl.firstChild(name: "payload") != nil else {
                throw SignalError.duplicateMessage;
            }
            throw SignalError.invalidMessage;
        }
        
        guard let ivStr = headerEl.firstChild(name: "iv")?.value, let iv = Data(base64Encoded: ivStr) else {
            throw SignalError.invalidArgument;
        }
        
        if decryptedKey.isPreKey {
            // pre key was removed so we need to republish the bundle!
            Task {
                let isPostponed = await state.postponedSession(for: message.type == .groupchat ? message.from?.bareJid : nil, address: decryptedKey.address)
                if !isPostponed {
                    if self.storage.preKeyStore.flushDeletedPreKeys() {
                        try? await self.publishDeviceBundleIfNeeded();
                    }
                }
            }
        }

        guard let payloadValue = encryptedEl.firstChild(name: "payload")?.value, let payload = Data(base64Encoded: payloadValue) else {
            return .transportKey(TransportKey(key: decryptedKey.data, iv: iv));
        }
        
        let body = try decrypt(payload: payload, iv: iv, key: decryptedKey);
        message.removeChild(encryptedEl);
        message.body = body;
        
        if let content = body, content.starts(with: "aesgcm://"), URLComponents(string: content) != nil {
            message.oob = content;
        }

        _ = storage.identityKeyStore.setStatus(active: true, forIdentity: senderAddress);
        return .message(DecryptedMessage(message: message, fingerprint: storage.identityKeyStore.identityFingerprint(forAddress: senderAddress)));
    }
    
    private func decrypt(payload: Data, iv: Data, key: DecryptedKey) throws -> String? {
        var decodedKey = key.data;
        
        var auth = Data();
        if decodedKey.count >= 32 {
            auth = decodedKey.subdata(in: 16..<decodedKey.count);
            decodedKey = decodedKey.subdata(in: 0..<16);
        }
        
        guard let sealed = try? AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: payload, tag: auth) else {
            throw SignalError.invalidArgument;
        }
        
        let key = SymmetricKey(data: decodedKey);
        guard let decoded = try? AES.GCM.open(sealed, using: key) else {
            logger.error("decoding of encrypted message failed!");
            throw SignalError.invalidMac;
        }
        
        return String(data: decoded, encoding: .utf8);
    }
    
    public func encrypt(message: Message, withStoreHint: Bool = true) async throws -> EncryptedMessage {
        guard let jid = message.to?.bareJid else {
            throw SignalError.noDestination;
        }
        
        return try await encrypt(message: message, for: [jid], withStoreHint: withStoreHint);
    }
    
    public func encrypt(message: Message, for jids: [BareJID], withStoreHint: Bool = true) async throws -> EncryptedMessage {
        let addresses = try await self.addresses(for: jids);
        await ensureSessions(forAddresses: addresses);
        return try self.encrypt(message: message, forAddresses: addresses, withStoreHint:  withStoreHint);
    }
     
    public func encrypt(message: Message, forAddresses addresses: [SignalAddress], withStoreHint: Bool = true) throws -> EncryptedMessage {
        let result = try _encrypt(message: message, for: addresses);
        result.message.body = self.defaultBody;
        if withStoreHint {
            result.message.addChild(Element(name: "store", xmlns: "urn:xmpp:hints"));
        }
        return result;
    }
    
    public func addresses(for jids: [BareJID]) async throws -> [SignalAddress] {
        guard let pubsubModule: PubSubModule = context?.module(.pubsub) else {
            throw SignalError.unknown;
        }
        
        return await jids.concurrentMapReduce({ jid in
            if let devices = await self.devices(for: jid) {
                return devices.map({ SignalAddress(name: jid.description, deviceId: $0) });
            } else {
                let items = try? await pubsubModule.retrieveItems(from: jid, for: OMEMOModule.DEVICES_LIST_NODE, limit: .lastItems(1));
                if let listEl = items?.items.first?.payload, listEl.name == "list" && listEl.xmlns == "eu.siacs.conversations.axolotl" {
                    let knownActiveDevices: [Int32] = listEl.compactMapChildren({$0.attribute("id") }).compactMap({ Int32($0) });
                        
                    
                    let allDevices = self.storage.sessionStore.allDevices(for: jid.description, activeAndTrusted: true);
                    allDevices.filter { (id) -> Bool in
                        return !knownActiveDevices.contains(id);
                        }.forEach { (deviceId) in
                            _ = self.storage.identityKeyStore.setStatus(active: false, forIdentity: SignalAddress(name: jid.description, deviceId: deviceId));
                    }
                    
                    knownActiveDevices.filter { (id) -> Bool in
                        return !allDevices.contains(id);
                        }.forEach { (deviceId) in
                            // TODO: we should enable this device key if we have its identity!
                            _ = self.storage.identityKeyStore.setStatus(active: true, forIdentity: SignalAddress(name: jid.description, deviceId: deviceId));
                    }
                    return knownActiveDevices.map({ SignalAddress(name: jid.description, deviceId: $0) });
                } else {
                    return [];
                }
            }
        })
    }
    
    private func ensureSessions(forAddresses addresses: [SignalAddress]) async {
        await addresses.filter({ !self.storage.sessionStore.containsSessionRecord(forAddress: $0) }).concurrentForEach({ await self.buildSession(forAddress: $0);
        })
    }
    
    public static func decryptFile(url localUrl: URL, fragment: String) throws -> Data {
        let data = try Data(contentsOf: localUrl)
        return try decryptFile(data: data, fragment: fragment);
    }
    
    public static func decryptFile(data inData: Data, fragment: String) throws -> Data {
        guard fragment.count % 2 == 0 && fragment.count > 64 && inData.count > 32 else {
            throw XMPPError(condition: .not_acceptable);
        }
        
        let ivLen = fragment.count - (32 * 2);
        let ivEndOffset = fragment.index(fragment.startIndex, offsetBy: ivLen - 1);
        let iv = Data(hex: fragment[...ivEndOffset]);
        let key = SymmetricKey(data: Data(hex: fragment[fragment.index(after: ivEndOffset)...]));
        
        let tag = inData.subdata(in: inData.count-16..<inData.count);
        let encodedData = inData.subdata(in: 0..<(inData.count-16));

        guard let sealed = try? AES.GCM.SealedBox(nonce: .init(data: iv), ciphertext: encodedData, tag: tag) else {
            throw XMPPError(condition: .not_acceptable);
        }

        guard let decoded = try? AES.GCM.open(sealed, using: key) else {
            throw XMPPError(condition: .not_acceptable);
        }

        return decoded;
    }
    
    public static func encryptFile(url: URL) throws -> (Data, String) {
        let data = try Data(contentsOf: url);
        return try encryptFile(data: data);
    }
    
    public static func encryptFile(data: Data) throws -> (Data, String) {
        let key = SymmetricKey(size: .bits256);

        guard let sealed = try? AES.GCM.seal(data, using: key) else {
            throw XMPPError(condition: .not_acceptable, message: "Invalid encryption key");
        }
        
        let combinedKey = Data(sealed.nonce) + key.data();

        return (sealed.ciphertext + sealed.tag, combinedKey.hex());
    }
    
    private func _encryptBody(_ body: String?, for key: SymmetricKey, nonce: AES.GCM.Nonce) -> (String?,Data) {
        if let data = body?.data(using: .utf8), let sealed = try? AES.GCM.seal(data, using: key, nonce: nonce) {
            return (sealed.ciphertext.base64EncodedString(), key.data() + sealed.tag);
        } else {
            return (nil, key.data());
        }
    }
    
    private func _encrypt(message: Message, for remoteAddresses: [SignalAddress], forSelf: Bool = true) throws -> EncryptedMessage {
        guard let context = self.context, let storage = signalContext.storage else {
            throw SignalError.unknown;
        }
        
        let key = SymmetricKey(size: .bits128);
        let encryptedEl = Element(name: "encrypted", xmlns: OMEMOModule.XMLNS);
        
        //        guard let data = message.body?.data(using: .utf8), let sealed = try? AES.GCM.seal(data, using: key) else {
        //            throw SignalError.notEncrypted;
        //        }
        let nonce = AES.GCM.Nonce();
        let (payload, combinedKey) = _encryptBody(message.body, for: key, nonce: nonce);
        if let payload = payload {
            encryptedEl.addChild(Element(name: "payload", cdata: payload));
        }
        let header = Element(name: "header");
        header.attribute("sid", newValue: String(storage.identityKeyStore.localRegistrationId()));
        encryptedEl.addChild(header);
        
        let localAddresses = forSelf ? storage.sessionStore.allDevices(for: context.userBareJid.description, activeAndTrusted: true).map({ (deviceId) -> SignalAddress in
            return SignalAddress(name: context.userBareJid.description, deviceId: deviceId);
        }) : [];
        let destinations: Set<SignalAddress> = Set(remoteAddresses + localAddresses);
        header.addChildren(destinations.compactMap({ addr -> SignalSessionCipher.Key? in
            // TODO: maybe we should cache this session?
            do {
                let cipher = try SignalSessionCipher(withAddress: addr, andContext: self.signalContext);
                return try cipher.encrypt(data: combinedKey);
            } catch {
                self.logger.error("Failed to encrypt key for \(addr): \(error)")
                return nil;
            }
        }).compactMap({ (key: SignalSessionCipher.Key) -> Element? in
            let keyEl = Element(name: "key", cdata: key.key.base64EncodedString());
            keyEl.attribute("rid", newValue: String(key.deviceId));
            if key.prekey {
                keyEl.attribute("prekey", newValue: "true");
            }
            return keyEl;
        }));
        header.addChild(Element(name: "iv", cdata: Data(nonce).base64EncodedString()));

        message.body = nil;
        message.addChild(Element(name: "store", xmlns: "urn:xmpp:hints"));
        message.addChild(encryptedEl);
        
        let fingerprint = storage.identityKeyStore.identityFingerprint(forAddress: SignalAddress(name: context.userBareJid.description, deviceId: Int32(bitPattern: storage.identityKeyStore.localRegistrationId())));
        return EncryptedMessage(message: message, fingerprint: fingerprint);
    }
    
//    private var mamSyncsInProgress: Set<BareJID?> = [];
    
    open func mamSyncStarted(for jid: BareJID?) {
        Task {
            await state.mamSyncStarted(for: jid);
        }
    }
    
    open func mamSyncFinished(for jid: BareJID?) {
        Task {
            await state.mamSyncFinished(for: jid);
            await self.processPostponed(for: jid);
        }
    }
    
    open override func onItemNotification(notification: PubSubModule.ItemNotification) {
        if notification.node == OMEMOModule.DEVICES_LIST_NODE, let context = self.context {
            switch notification.action {
            case .published(let item):
                let from = notification.message.from?.bareJid ?? context.userBareJid;
                Task {
                    await checkAndPublishDevicesListIfNeeded(jid: from, list: item.payload)
                }
            default:
                break;
            }
        }
    }
    
    private func publishDeviceIdIfNeeded(removeDevicesWithIds: [UInt32]? = nil) async {
        guard isPepAvailable, let context = context else {
            return;
        }
        let pepJid = context.userBareJid;
        do {
            let items = try await context.module(.pubsub).retrieveItems(from: pepJid, for: OMEMOModule.DEVICES_LIST_NODE, limit: .lastItems(1));
            await checkAndPublishDevicesListIfNeeded(jid: pepJid, list: items.items.first?.payload, removeDevicesWithIds: removeDevicesWithIds)
        } catch let error as XMPPError {
            guard error.condition == .item_not_found || error.condition == .internal_server_error else {
                return;
            }
            await checkAndPublishDevicesListIfNeeded(jid: pepJid, list: nil)
        } catch {
            // nothing to do..
        }
    }

    private func checkAndPublishDevicesListIfNeeded(jid: BareJID, list input: Element?, removeDevicesWithIds: [UInt32]? = nil) async {
        guard let context = context else {
            return;
        }
        
        let pubsubModule = context.module(.pubsub);
        var listEl = input;

        if listEl?.name != "list" || listEl?.xmlns != "eu.siacs.conversations.axolotl" {
            listEl = Element(name: "list", xmlns: "eu.siacs.conversations.axolotl");
        }
        
        
        let me = context.userBareJid == jid;
        
        if me {
            var changed = false;
            
            if removeDevicesWithIds != nil && listEl != nil {
                let deviceIds = removeDevicesWithIds!.map { (deviceId) -> String in
                    return String(deviceId);
                }
                listEl!.removeChildren(where: { (el) -> Bool in
                    guard let id = el.attribute("id") else {
                        return false;
                    }
                    return deviceIds.contains(id);
                });
                changed = true;
            }
        
            let ourDeviceId = self.storage.identityKeyStore.localRegistrationId();
            let ourDeviceIdStr = String(ourDeviceId);
            if listEl?.firstChild(where: { (deviceEl) -> Bool in
                deviceEl.attribute("id") == ourDeviceIdStr;
            }) == nil {
                listEl?.addChild(Element(name: "device", attributes: ["id": ourDeviceIdStr]));
                changed = true;
            }
        
            if changed {
                let publishOptions = PubSubNodeConfig();
                publishOptions.accessModel = .open
                do {
                    _ = try await pubsubModule.publishItem(at: jid, to: OMEMOModule.DEVICES_LIST_NODE, itemId: "current", payload: listEl!, publishOptions: publishOptions);
                    self.isReady = true;
                    logger.debug("device id: \(ourDeviceIdStr) successfully registered!");
                } catch let error as XMPPError {
                    guard error.condition == .conflict else {
                        return;
                    }
                    do {
                        let form = try await pubsubModule.retrieveNodeConfiguration(from: jid, node: OMEMOModule.DEVICES_LIST_NODE);
                        form.accessModel = .open;
                        do {
                            try await pubsubModule.configureNode(at: jid, node: OMEMOModule.DEVICES_LIST_NODE, with: form);
                            _ = try? await pubsubModule.publishItem(at: jid, to: OMEMOModule.DEVICES_LIST_NODE, itemId: "current", payload: listEl!, publishOptions: publishOptions);
                            self.isReady = true;
                        } catch {
                            logger.error("node reconfiguration failed! \(error)");
                        }
                    } catch {
                        logger.debug("node configuration retrieval failed! \(error)");
                    }
                } catch {
                    logger.error("could not publish devices list: \(error)");
                }
            } else {
                self.isReady = true;
            }
        }
        
        let knownActiveDevices = listEl!.compactMapChildren({ el -> Int32? in
            guard let id = el.attribute("id") else {
                return nil;
            }
            return Int32(id);
        });
        
        let allDevices = storage.sessionStore.allDevices(for: jid.description, activeAndTrusted: true);
        allDevices.filter { (id) -> Bool in
            return !knownActiveDevices.contains(id);
            }.forEach { (deviceId) in
                _ = storage.identityKeyStore.setStatus(active: false, forIdentity: SignalAddress(name: jid.description, deviceId: deviceId));
        }
        
        knownActiveDevices.filter { (id) -> Bool in
            return !allDevices.contains(id);
            }.forEach { (deviceId) in
                // TODO: we should enable this device key if we have its identity!
                _ = storage.identityKeyStore.setStatus(active: true, forIdentity: SignalAddress(name: jid.description, deviceId: deviceId));
        }
        
        if me {
            let brokenIds = await state.clearOwnBrokenDevices();
            if !brokenIds.isEmpty {
                await self.removeDevices(withIds: brokenIds);
            }
            
            await ensureSessions(forAddresses: knownActiveDevices.filter({ $0 != self.storage.identityKeyStore.localRegistrationId() }).compactMap({ SignalAddress(name: jid.description, deviceId: $0) }));
        }
        await state.updateKnownActiveDevices(knownActiveDevices, for: jid);
        self.activeDevicesPublisher.send(AvailabilityChanged(jid: jid, activeDevices: knownActiveDevices));
    }
    
    private func publishDeviceBundleIfNeeded() async throws {
        guard let pepJid = context?.userBareJid, let pubsubModule = context?.module(.pubsub) else {
            throw SignalError.unknown;
        }
        
        do {
            let items = try await pubsubModule.retrieveItems(from: pepJid, for: bundleNode(for: storage.identityKeyStore.localRegistrationId()), limit: .items(withIds: ["current"]));
            try await self.publishDeviceBundle(currentBundle: items.items.first?.payload);
        } catch let error as XMPPError {
            guard error.condition == .item_not_found || error.condition == .internal_server_error else {
                return;
            }
            try await self.publishDeviceBundle(currentBundle: nil);
        }
    }
    
    public func removeDevices(withIds: [Int32]) {
        Task {
            await removeDevices(withIds: withIds);
        }
    }
    
    public func removeDevices(withIds: [Int32]) async {
        guard let pepJid = context?.userBareJid, let pubsubModule = context?.module(.pubsub) else {
            return;
        }
        
        let ids = withIds.map { (deviceId) -> UInt32 in
            return UInt32(bitPattern: deviceId);
        }
        
        for deviceId in withIds {
            _ = self.storage.identityKeyStore.setStatus(active: false, forIdentity: SignalAddress(name: pepJid.description, deviceId: deviceId));
            
            Task {
                try? await pubsubModule.deleteNode(from: pepJid, node: bundleNode(for: UInt32(bitPattern: deviceId)));
            }
        }
        
        await self.publishDeviceIdIfNeeded(removeDevicesWithIds: ids);
    }
    
    private func processPostponed(for jid: BareJID?) async {
        if let sessions = await state.removePostponedSessions(for: jid) {
            if !sessions.isEmpty {
                if self.storage.preKeyStore.flushDeletedPreKeys() {
                    try? await self.publishDeviceBundleIfNeeded();
                }
            }
            
            for address in sessions {
                self.completeSession(forAddress: address);
            }
        }
        if let healings = await state.removePostponedHealing(for: jid) {
            await healings.concurrentForEach({ await self.buildSession(forAddress: $0) });
        }
    }
    
    fileprivate func signedPreKey(regenerate: Bool = false) -> SignalSignedPreKey? {
        let signedPreKeyId = storage.signedPreKeyStore.countSignedPreKeys();
        var signedPreKey: SignalSignedPreKey? = nil;
        if (!regenerate) && (signedPreKeyId != 0) {
            if let data = signalContext.storage?.signedPreKeyStore.loadSignedPreKey(withId: UInt32(signedPreKeyId)) {
                signedPreKey = SignalSignedPreKey(fromSerializedData: data);
            }
        }
        
        if signedPreKey == nil {
            let identityKeyPair = storage.identityKeyStore.keyPair()!;
            logger.info("regenerating signed pre key!");
            signedPreKey = signalContext.generateSignedPreKey(withIdentity: identityKeyPair, signedPreKeyId: UInt32(signedPreKeyId + 1))
            guard signedPreKey != nil else {
                return nil;
            }
            guard signalContext.storage?.signedPreKeyStore.storeSignedPreKey(signedPreKey!.serializedData!, withId: signedPreKey!.preKeyId) ?? false else {
                return nil;
            }
        }
        return signedPreKey;
    }

    private func publishDeviceBundle(currentBundle: Element?) async throws {
        guard let identityKeyPair = storage.identityKeyStore.keyPair() else {
            return;
        }
        guard let identityPublicKey = identityKeyPair.publicKeyData?.base64EncodedString() else {
            return;
        }

        var flush: Bool = currentBundle == nil;
        if !flush {
            flush = identityPublicKey != currentBundle?.firstChild(name: "identityKey")?.value;
        }
        
        if let signedPreKey = self.signedPreKey(regenerate: flush), let signedPreKeyBase64 = signedPreKey.publicKeyData?.base64EncodedString() {
            let signatureBase64 = signedPreKey.signature.base64EncodedString();
            var changed = flush || signedPreKeyBase64 != currentBundle?.firstChild(name: "signedPreKeyPublic")?.value || signatureBase64 != currentBundle?.firstChild(name: "signedPreKeySignature")?.value;
            
            let currentKeys =  currentBundle?.firstChild(name: "prekeys")?.compactMapChildren({ preKeyEl -> UInt32? in
                guard let preKeyId = preKeyEl.attribute("preKeyId") else {
                    return nil;
                }
                return UInt32(preKeyId);
            });
            
            var invalidKeys: [UInt32] = []
            var validKeys = currentKeys?.map({ (preKeyId) -> SignalPreKey? in
                guard let key = self.storage.preKeyStore.loadPreKey(withId: preKeyId) else {
                    return nil;
                }
                return SignalPreKey(fromSerializedData: key);
            }).map({ key -> SignalPreKey? in
                guard let key else {
                    return nil;
                }
                guard key.validate(identityKey: identityKeyPair, signedPreKeySignature: signedPreKey.signature) else {
                    invalidKeys.append(key.preKeyId)
                    _ = self.storage.preKeyStore.deletePreKey(withId: key.preKeyId)
                    return nil;
                }
                return key;
            }).filter({ preKey -> Bool in
                return preKey != nil;
            }).map({ preKey -> SignalPreKey in
                return preKey!;
            }) ?? [];
            
            if (!invalidKeys.isEmpty) {
                let account = context?.userBareJid.description
                logger.debug("for account \(account ?? "nil") had following invalid pre keys: \(invalidKeys.sorted()) and were deleted...")
            }
                        
            let needKeys = 100 - validKeys.count;
            if needKeys > 0 {
                changed = true;
                let currentPreKeyId = self.storage.preKeyStore.currentPreKeyId();
                var newKeys = self.signalContext.generatePreKeys(withStartingPreKeyId: currentPreKeyId + 1, count: UInt32(needKeys));
                newKeys = newKeys.filter { (key) in
                    self.storage.preKeyStore.storePreKey(key.serializedData!, withId: key.preKeyId);
                };
                validKeys = validKeys + newKeys;
            }

            if changed {
                // something has changed, we need to publish new bundle!
                try await publishDeviceBundle(signedPreKey: signedPreKey, preKeys: validKeys);
            } else {
                return;
            }
        }
    }

    private func publishDeviceBundle(signedPreKey: SignalSignedPreKey, preKeys: [SignalPreKey]) async throws {
        let identityKeyPair = storage.identityKeyStore.keyPair()!;
        
        let bundleEl = Element(name: "bundle", xmlns: OMEMOModule.XMLNS);
        bundleEl.addChild(Element(name: "signedPreKeyPublic", cdata: signedPreKey.publicKeyData!.base64EncodedString(), attributes: ["signedPreKeyId": String(signedPreKey.preKeyId)]));
        bundleEl.addChild(Element(name: "signedPreKeySignature", cdata: signedPreKey.signature.base64EncodedString()));
        bundleEl.addChild(Element(name: "identityKey", cdata: identityKeyPair.publicKeyData!.base64EncodedString()));
        let preKeysElems = preKeys.map({ (preKey) -> Element in
            return Element(name: "preKeyPublic", cdata: preKey.serializedPublicKey!.base64EncodedString(), attributes: ["preKeyId": String(preKey.preKeyId)]);
        });
        bundleEl.addChild(Element(name: "prekeys", children: preKeysElems));
        
        let publishOptions = PubSubNodeConfig();
        publishOptions.accessModel = .open;
        
        guard let pubsubModule = context?.module(.pubsub) else {
            return;
        }
        _ = try await pubsubModule.publishItem(at: nil, to: bundleNode(for: storage.identityKeyStore.localRegistrationId()), itemId: "current", payload: bundleEl, publishOptions: publishOptions);
    }
    
    public func regenerateSession(forAddress address: SignalAddress) async throws {
        await buildSession(forAddress: address)
        completeSession(forAddress: address);
    }
    
    private func completeSession(forAddress address: SignalAddress) {
        let message = Message(type: .chat, to: JID(address.name));
        do {
            let message = try _encrypt(message: message, for: [address], forSelf: false).message;
            message.hints = [.store];
            self.write(stanza: message);
        } catch {
            logger.error("failed to complete session for address: \(address), error: \(error)");
        }
    }
    
    private func buildSession(forAddress address: SignalAddress) async {
        let pepJid = BareJID(address.name);
        guard let pubsubModule: PubSubModule = context?.module(.pubsub) else {
            return;
        }
        do {
            let items = try await pubsubModule.retrieveItems(from: pepJid, for: bundleNode(for: UInt32(bitPattern: address.deviceId)), limit: .lastItems(1));
            guard let bundle = OMEMOBundle(from: items.items.first?.payload) else {
                logger.debug("could not create a bundle!");
                await state.markDeviceFailed(for: pepJid, deviceId: address.deviceId);
                return;
            }
        
            let preKey = bundle.preKeys[Int.random(in: 0..<bundle.preKeys.count)];
            do {
                let preKeyBundle = try SignalPreKeyBundle(registrationId: 0, deviceId: address.deviceId, preKey: preKey, bundle: bundle)
                do {
                    let builder = try SignalSessionBuilder(withAddress: address, andContext: self.signalContext);
                    try builder.processPreKeyBundle(bundle: preKeyBundle);
                } catch {
                    logger.error("building session failed: \(error)");
                }
            } catch {
                logger.error("unable to create pre key bundle!");
                await state.markDeviceFailed(for: pepJid, deviceId: address.deviceId);
            }
        } catch {
            if let err = error as? XMPPError, let account = self.context?.userBareJid, err.condition == .item_not_found, account == pepJid {
                // there is not bundle for local device-id
                await state.markOwnBroken(deviceId: address.deviceId);
            } else {
                await state.markDeviceFailed(for: pepJid, deviceId: address.deviceId);
            }
        }
    }
    
    private func bundleNode(for deviceId: UInt32) -> String {
        return "eu.siacs.conversations.axolotl.bundles:\(deviceId)";
    }
    
    open class OMEMOBundle {
        
        let preKeys: [OMEMOPreKey];
        
        let signedPreKeyId: UInt32;
        let signedPreKeyPublic: Data;
        let identityKey: Data;
        let signature: Data;
        
        init?(from: Element?) {
            guard let el = from, el.name == "bundle" && el.xmlns == OMEMOModule.XMLNS else {
                return nil;
            }
            
            guard let preKeys = el.firstChild(name: "prekeys")?.compactMapChildren(OMEMOPreKey.init(from:)), !preKeys.isEmpty else {
                return nil;
            }
            
            guard let signedKeyPublic = el.firstChild(name: "signedPreKeyPublic"), let signedPreKeyIdStr = signedKeyPublic.attribute("signedPreKeyId"), let signedPreKeyId = UInt32(signedPreKeyIdStr), let signedKeyPublicValue = signedKeyPublic.value, let signedKeyPublicData = Data(base64Encoded: signedKeyPublicValue, options: [.ignoreUnknownCharacters]) else {
                return nil;
            }

            guard let identityKeyValue = el.firstChild(name: "identityKey")?.value, let identityKeyData = Data(base64Encoded: identityKeyValue, options: [.ignoreUnknownCharacters]) else {
                return nil;
            }

            guard let signatureValue = el.firstChild(name: "signedPreKeySignature")?.value, let signatureData = Data(base64Encoded: signatureValue, options: [.ignoreUnknownCharacters]) else {
                return nil;
            }
            
            self.signedPreKeyId = signedPreKeyId;
            self.signedPreKeyPublic = signedKeyPublicData;
            self.signature = signatureData;
            self.identityKey = identityKeyData;
            self.preKeys = preKeys;
        }
        
    }
    
    public struct OMEMOPreKey {
        
        public let preKeyId: UInt32;
        public let data: Data;
        
        public init?(from: Element) {
            guard from.name == "preKeyPublic", let value = from.value, let preKeyIdStr = from.attribute("preKeyId") else {
                return nil;
            }
            guard let data = Data(base64Encoded: value, options: [.ignoreUnknownCharacters]), let preKeyId = UInt32(preKeyIdStr) else {
                return nil;
            }
            
            self.init(data: data, preKeyId: preKeyId);
        }

        public init(data: Data, preKeyId: UInt32) {
            self.data = data;
            self.preKeyId = preKeyId;
        }

    }
    
    public struct AvailabilityChanged {
        
        public let jid: BareJID;
        public let activeDevices: [Int32];
        
    }
    
}

public struct EncryptedMessage {
    public let message: Message;
    public let fingerprint: String?;
}

public struct DecryptedMessage {
    public let message: Message;
    public let fingerprint: String?;
}

public struct TransportKey {
    public let key: Data;
    public let iv: Data;
}

public enum DecryptionResult {
    case message(DecryptedMessage)
    case transportKey(TransportKey)
}

// methods kept for compatibility
extension OMEMOModule {
 
    public func encode(message: Message, withStoreHint: Bool = true, completionHandler: @escaping (Result<EncryptedMessage, Error>)->Void) {
        Task {
            do {
                completionHandler(.success(try await encrypt(message: message, withStoreHint: true)))
            } catch {
                completionHandler(.failure(error));
            }
        }
    }
    
    public func addresses(for jids: [BareJID], completionHandler: @escaping(Result<[SignalAddress],Error>)->Void) {
        Task {
            do {
                completionHandler(.success(try await addresses(for: jids)));
            } catch {
                completionHandler(.failure(error))
            }
        }
    }
    
    public func encode(message: Message, for jids: [BareJID], withStoreHint: Bool = true, completionHandler: @escaping (Result<EncryptedMessage, Error>)->Void) {
        Task {
            do {
                completionHandler(.success(try await self.encrypt(message: message, for: jids, withStoreHint: withStoreHint)))
            } catch {
                completionHandler(.failure(error));
            }
        }
    }
    
    public func isAvailable(for jid: BareJID, completionHandler: @escaping (Bool)->Void) {
        Task {
            completionHandler(await isAvailable(for: jid));
        }
    }


}
