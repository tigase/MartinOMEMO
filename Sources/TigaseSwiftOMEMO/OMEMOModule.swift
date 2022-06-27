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
import TigaseSwift
import libsignal
import Combine
import CryptoKit

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

open class OMEMOModule: AbstractPEPModule, XmppModule, Resetable {
    
    public static let ID = "omemo";
    public static let IDENTIFIER = XmppModuleIdentifier<OMEMOModule>();
    public static let XMLNS = "eu.siacs.conversations.axolotl";
    public static let DEVICES_LIST_NODE = "eu.siacs.conversations.axolotl.devicelist";
    
    public let id: String = ID;

    // Default body to set for OMEMO encrypted messages
    open var defaultBody: String? = "I sent you an OMEMO encrypted message but your client doesn’t seem to support that.";
    
    public override var isPepAvailable: Bool {
        didSet {
            if isPepAvailable {
                publishDeviceBundleIfNeeded() {
                    self.publishDeviceIdIfNeeded();
                }
            }
        }
    }

    public let criteria = Criteria.empty();

    public let features: [String] = [OMEMOModule.DEVICES_LIST_NODE + "+notify"];
    
    public let signalContext: SignalContext;
    public let storage: SignalStorage;
    fileprivate let devicesQueue: DispatchQueue = DispatchQueue(label: "omemo_devices_dispatch_queue");
    fileprivate var devices: [BareJID: [Int32]] = [:];
    fileprivate var devicesFetchError: [BareJID: [Int32]] = [:];
    private var ownBrokenDevices: [Int32] = [];

    @Published
    public private(set) var isReady: Bool = false;
    
    public let activeDevicesPublisher = PassthroughSubject<AvailabilityChanged,Never>();
    
    public func isAvailable(for jid: BareJID) -> Bool {
        return (!(self.devicesQueue.sync(execute: { self.devices[jid] })?.isEmpty ?? true)) || !self.storage.sessionStore.allDevices(for: jid.description, activeAndTrusted: true).isEmpty;
    }
    
    public init(signalContext: SignalContext, signalStorage: SignalStorage) {
        self.signalContext = signalContext;
        self.storage = signalStorage;
        super.init();
    }
    
    public func reset(scopes: Set<ResetableScope>) {
        if scopes.contains(.session) {
            self.isReady = false;
            self.devicesQueue.async {
                self.devices.removeAll();
            }
        }
    }
    
    public func regenerateKeys(wipe: Bool = false) -> Bool {
        let regenerated = self.storage.regenerateKeys(wipe: wipe);
        if regenerated && isPepAvailable {
            self.publishDeviceBundle(currentBundle: nil) {
                self.publishDeviceIdIfNeeded();
            }
        }
        return regenerated;
    }
    
    public func devices(for jid: BareJID) -> [Int32]? {
        guard let devices = self.devicesQueue.sync(execute: { self.devices[jid] }) else {
            return nil;
        }
        guard let failed = self.devicesFetchError[jid] else {
            return devices;
        }
        return devices.filter({ (deviceId) -> Bool in
            return !failed.contains(deviceId);
        });
    }

    
    public func process(stanza: Stanza) throws {
        throw XMPPError(condition: .feature_not_implemented);
    }
    
    public func decode(message: Message, serverMsgId: String? = nil) -> DecryptionResult<Message, SignalError> {
        guard let from = message.from?.bareJid else {
            return .failure(.invalidArgument);
        }
        return self.decode(message: message, from: from, serverMsgId: serverMsgId);
    }
    
    
    public func decode(message: Message, from: BareJID, serverMsgId: String? = nil) -> DecryptionResult<Message, SignalError> {
        guard let context = context else {
            return .failure(.unknown);
        }

        guard let encryptedEl = message.firstChild(name: "encrypted", xmlns: OMEMOModule.XMLNS) else {
            return .failure(SignalError.notEncrypted);
        }
        
        guard let headerEl = encryptedEl.firstChild(name: "header"), let sid = UInt32(headerEl.attribute("sid") ?? "") else {
            return .failure(.invalidArgument);
        }
        
        let localDeviceIdStr = String(signalContext.storage.identityKeyStore.localRegistrationId());
        
        guard headerEl.firstChild(where: { (el) -> Bool in
            return el.name == "key" && el.attribute("rid") == localDeviceIdStr;
        }) != nil else {
            guard context.userBareJid != from || sid != signalContext.storage.identityKeyStore.localRegistrationId() else {
                return .failure(.duplicateMessage);
            }
            guard encryptedEl.firstChild(name: "payload") != nil else {
                return .failure(.duplicateMessage);
            }
            return .failure(.invalidMessage);
        }
        
        let possibleKeys = headerEl.filterChildren(where: { (el) -> Bool in
            return el.name == "key" && el.attribute("rid") == localDeviceIdStr;
        }).map({ (keyEl) -> KeyDecryptionResult in
            let prekey = "true" == keyEl.attribute("prekey") || keyEl.attribute("prekey") == "1";
            let address = SignalAddress(name: from.description, deviceId: Int32(bitPattern: sid));
            guard let keyElValue = keyEl.value, let key = Data(base64Encoded: keyElValue) else {
                return .init(result: .failure(.invalidArgument), address: address, isPrekey: prekey);
            }
            guard let session = SignalSessionCipher(withAddress: address, andContext: self.signalContext) else {
                return .init(result: .failure(SignalError.noMemory), address: address, isPrekey: prekey);
            }
            return .init(result: session.decrypt(key: SignalSessionCipher.Key(key: key,deviceId: Int32(bitPattern: sid), prekey: prekey)), address: address, isPrekey: prekey);
        });
        
        guard let possibleKey = possibleKeys.first(where: { $0.isSuccess }) else {
            if let key = possibleKeys.first {
                switch key.result {
                case .failure(let error):
                    switch error {
                    case .noSession, .invalidMessage:
                        if serverMsgId != nil {
                            if !postponeHealing(for: message.type == .groupchat ? message.from?.bareJid : nil, address: key.address) {
                                self.buildSession(forAddress: key.address, completionHandler: {
                                    self.completeSession(forAddress: key.address);
                                });
                            }
                        }
                    default:
                        break;
                    }
                    return .failure(error);
                case .success(_):
                    return .failure(.unknown);
                }
            } else {
                guard encryptedEl.hasChild(name: "payload") else {
                    return .failure(.duplicateMessage);
                }
                return .failure(.invalidMessage);
            }
        }
        
        switch possibleKey.result {
        case .failure(let error):
            return .failure(error);
        case .success(let data):
            message.removeChild(encryptedEl);

            let address = possibleKey.address;
            let prekey = possibleKey.isPrekey;
            var decodedKey = data;
            
            if prekey {
                // pre key was removed so we need to republish the bundle!
                if !postponeSession(for: message.type == .groupchat ? message.from?.bareJid : nil, address: address) {
                    if self.storage.preKeyStore.flushDeletedPreKeys() {
                        self.publishDeviceBundleIfNeeded(completionHandler: nil);
                    }
                }
            }

            var auth = Data();
            if decodedKey.count >= 32 {
                auth = decodedKey.subdata(in: 16..<decodedKey.count);
                decodedKey = decodedKey.subdata(in: 0..<16);
            }
            
            
            guard let ivStr = headerEl.firstChild(name: "iv")?.value, let iv = Data(base64Encoded: ivStr) else {
                return .failure(.invalidArgument);
            }
            
            guard let payloadValue = encryptedEl.firstChild(name: "payload")?.value, let payload = Data(base64Encoded: payloadValue) else {
                return .successTransportKey(decodedKey, iv: iv);
            }

            guard let sealed = try? AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: payload, tag: auth) else {
                return .failure(.invalidArgument);
            }
            
            let key = SymmetricKey(data: decodedKey);
            guard let decoded = try? AES.GCM.open(sealed, using: key) else {
                print("decoding of encrypted message failed!");
                return .failure(.invalidMac);
            }
            
            let body = String(data: decoded, encoding: .utf8);
            message.body = body;
            
            if let content = body, content.starts(with: "aesgcm://"), URLComponents(string: content) != nil {
                message.oob = content;
            }

            _ = storage.identityKeyStore.setStatus(active: true, forIdentity: address);
            return .successMessage(message, fingerprint: storage.identityKeyStore.identityFingerprint(forAddress: address));
        }
    }
    
    public func encode(message: Message, withStoreHint: Bool = true, completionHandler: @escaping (EncryptionResult<Message, SignalError>)->Void) {
        guard let jid = message.to?.bareJid else {
            completionHandler(.failure(.noDestination));
            return;
        }

        encode(message: message, for: [jid], withStoreHint: withStoreHint, completionHandler: completionHandler);
    }
    
    public func addresses(for jids: [BareJID], completionHandler: @escaping(Result<[SignalAddress],SignalError>)->Void) {
        guard let pubsubModule: PubSubModule = context?.module(.pubsub) else {
            completionHandler(.failure(.unknown));
            return;
        }
        let group = DispatchGroup();
        var addresses: [SignalAddress] = [];
        for jid in jids {
            if let devices = self.devices(for: jid) {
                addresses.append(contentsOf: devices.map({ SignalAddress(name: jid.description, deviceId: $0) }));
                for address in addresses.filter({ !self.storage.sessionStore.containsSessionRecord(forAddress: $0) }) {
                    group.enter();
                    self.buildSession(forAddress: address, completionHandler: {
                        group.leave();
                    })
                }
            } else {
                group.enter();
                pubsubModule.retrieveItems(from: jid, for: OMEMOModule.DEVICES_LIST_NODE, limit: .lastItems(1), completionHandler: { result in
                    switch result {
                    case .success(let items):
                        print("got published devices from:", jid, ", ", items.items.first as Any);
                        if let listEl = items.items.first?.payload, listEl.name == "list" && listEl.xmlns == "eu.siacs.conversations.axolotl" {
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
                            addresses.append(contentsOf: knownActiveDevices.map({ SignalAddress(name: jid.description, deviceId: $0) }));
                        }
                        
                        // should we start fetching sessions here? without waiting for all JIDs to return? should improve performance
                        for address in addresses.filter({ !self.storage.sessionStore.containsSessionRecord(forAddress: $0) }) {
                            group.enter();
                            self.buildSession(forAddress: address, completionHandler: {
                                group.leave();
                            })
                        }
                    case .failure(_):
                        break;
                    }
                    group.leave();
                })
            }
        }
        group.notify(queue: DispatchQueue.main, execute: {
            // we finished address retrieval..
            completionHandler(.success(addresses));
        })
    }
    
    public func encode(message: Message, for jids: [BareJID], withStoreHint: Bool = true, completionHandler: @escaping (EncryptionResult<Message, SignalError>)->Void) {
        
        addresses(for: jids, completionHandler: { result in
            switch result {
            case .failure(let error):
                completionHandler(.failure(error));
            case .success(let addresses):
                if addresses.isEmpty {
                    completionHandler(.failure(.noSession));
                } else {
                    self.encode(message: message, forAddresses: addresses, withStoreHint: withStoreHint, completionHandler: completionHandler);
                }
            }
            
        })
    }
     
    public func encode(message: Message, forAddresses addresses: [SignalAddress], withStoreHint: Bool = true, completionHandler: @escaping (EncryptionResult<Message, SignalError>)->Void) {

        let result = self._encode(message: message, for: addresses);
        
        switch result {
        case .successMessage(let encodedMessage, _):
            encodedMessage.body = self.defaultBody;
            if withStoreHint {
                encodedMessage.addChild(Element(name: "store", xmlns: "urn:xmpp:hints"));
            }
        default:
            break;
        }
        
        completionHandler(result);
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
    
    private func _encode(message: Message, for remoteAddresses: [SignalAddress], forSelf: Bool = true) -> EncryptionResult<Message,SignalError> {
        guard let context = self.context else {
            return .failure(.unknown);
        }
        
        let key = SymmetricKey(size: .bits128);
        let encryptedEl = Element(name: "encrypted", xmlns: OMEMOModule.XMLNS);

        guard let data = message.body?.data(using: .utf8), let sealed = try? AES.GCM.seal(data, using: key) else {
            return .failure(.notEncrypted);
        }
                    
        encryptedEl.addChild(Element(name: "payload", cdata: sealed.ciphertext.base64EncodedString()));
                
        let combinedKey = key.data() + sealed.tag;
        let header = Element(name: "header");
        header.attribute("sid", newValue: String(signalContext.storage.identityKeyStore.localRegistrationId()));
        encryptedEl.addChild(header);
        
        let localAddresses = forSelf ? storage.sessionStore.allDevices(for: context.userBareJid.description, activeAndTrusted: true).map({ (deviceId) -> SignalAddress in
            return SignalAddress(name: context.userBareJid.description, deviceId: deviceId);
        }) : [];
        let destinations: Set<SignalAddress> = Set(remoteAddresses + localAddresses);
        header.addChildren(destinations.map({ (addr) -> Result<SignalSessionCipher.Key,SignalError> in
                // TODO: maybe we should cache this session?
                guard let session = SignalSessionCipher(withAddress: addr, andContext: self.signalContext) else {
                    return .failure(.noMemory);
                }
                return session.encrypt(data: combinedKey);
            }).map({ (result) -> Element? in
                switch result {
                case .success(let key):
                    let keyEl = Element(name: "key", cdata: key.key.base64EncodedString());
                    keyEl.attribute("rid", newValue: String(key.deviceId));
                    if key.prekey {
                        keyEl.attribute("prekey", newValue: "true");
                    }
                    return keyEl;
                case .failure(_):
                    return nil;
                }
            }).filter({ (el) -> Bool in
                return el != nil;
            }).map({ el -> Element in
                return el!;
            }));
            header.addChild(Element(name: "iv", cdata: Data(sealed.nonce).base64EncodedString()));

        message.body = nil;
        message.addChild(Element(name: "store", xmlns: "urn:xmpp:hints"));
        message.addChild(encryptedEl);
        
        let fingerprint = storage.identityKeyStore.identityFingerprint(forAddress: SignalAddress(name: context.userBareJid.description, deviceId: Int32(bitPattern: storage.identityKeyStore.localRegistrationId())));
        return .successMessage(message, fingerprint: fingerprint);
    }
    
    private var mamSyncsInProgress: Set<BareJID?> = [];
    
    open func mamSyncStarted(for jid: BareJID?) {
        self.devicesQueue.sync {
            self.mamSyncsInProgress.insert(jid);
            self.postponedSessions[jid] = [];
        }
    }
    
    open func mamSyncFinished(for jid: BareJID?) {
        self.devicesQueue.sync {
            self.mamSyncsInProgress.remove(jid);
            self.processPostponed(for: jid);
        }
    }
    
    open override func onItemNotification(notification: PubSubModule.ItemNotification) {
        if notification.node == OMEMOModule.DEVICES_LIST_NODE, let context = self.context {
            switch notification.action {
            case .published(let item):
                let from = notification.message.from?.bareJid ?? context.userBareJid;
                checkAndPublishDevicesListIfNeeded(jid: from, list: item.payload)
            default:
                break;
            }
        }
    }
    
    func publishDeviceIdIfNeeded(removeDevicesWithIds: [UInt32]? = nil) {
        guard isPepAvailable, let context = context else {
            return;
        }
        let pepJid = context.userBareJid;
        context.module(.pubsub).retrieveItems(from: pepJid, for: OMEMOModule.DEVICES_LIST_NODE, limit: .lastItems(1), completionHandler: { result in
            switch result {
            case .success(let items):
                print("got published devices:", items.items.first as Any);
                self.checkAndPublishDevicesListIfNeeded(jid: pepJid, list: items.items.first?.payload, removeDevicesWithIds: removeDevicesWithIds);
            case .failure(let error):
                guard error.condition == .item_not_found || error.condition == .internal_server_error else {
                    return;
                }
                self.checkAndPublishDevicesListIfNeeded(jid: pepJid, list: nil);
            }
        });
    }
        
    fileprivate func checkAndPublishDevicesListIfNeeded(jid: BareJID, list input: Element?, removeDevicesWithIds: [UInt32]? = nil) {
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
                pubsubModule.publishItem(at: jid, to: OMEMOModule.DEVICES_LIST_NODE, itemId: "current", payload: listEl!, publishOptions: publishOptions, completionHandler: { result in
                    switch result {
                    case .success(_):
                        self.isReady = true;
                        print("device id:", ourDeviceIdStr, " successfully registered!");
                    case .failure(let error):
                        print("item registration failed!");
                        if error.condition == .conflict {
                            pubsubModule.retrieveNodeConfiguration(from: jid, node: OMEMOModule.DEVICES_LIST_NODE, completionHandler: { result in
                                switch result {
                                case .success(let form):
                                    form.accessModel = .open;
                                    pubsubModule.configureNode(at: jid, node: OMEMOModule.DEVICES_LIST_NODE, with: form, completionHandler: { result in
                                        switch result {
                                        case .success(_):
                                            pubsubModule.publishItem(at: jid, to: OMEMOModule.DEVICES_LIST_NODE, itemId: "current", payload: listEl!, publishOptions: publishOptions, completionHandler: { result in
                                                switch result {
                                                case .success(_):
                                                    self.isReady = true;
                                                    print("device id:", ourDeviceIdStr, " successfully registered 2!");
                                                case .failure(let error):
                                                    print("item registration failed 2! \(error)");
                                                }
                                            });
                                        case .failure(let error):
                                            print("node reconfiguration failed! \(error)");
                                        }
                                    });
                                case .failure(let error):
                                    print("node configuration retrieval failed! \(error)");
                                }
                            });
                        }
                    }
                });
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
            let group = DispatchGroup();
            group.notify(queue: self.devicesQueue, execute: {
                let brokenIds = self.ownBrokenDevices;
                guard !brokenIds.isEmpty else {
                    return;
                }
              
                self.ownBrokenDevices.removeAll();
                
                print("removing own devices with ids \(brokenIds) as there are no bundles for them!")
                self.removeDevices(withIds: brokenIds);
            })
            
            group.enter();
            knownActiveDevices.forEach { (deviceId) in
                guard deviceId != self.storage.identityKeyStore.localRegistrationId() else {
                    return;
                }
                let address = SignalAddress(name: jid.description, deviceId: deviceId);
                if !self.storage.sessionStore.containsSessionRecord(forAddress: address) {
                    // we do not have a session, so we need to build one!
                    group.enter();
                    self.buildSession(forAddress: address, completionHandler: {
                        group.leave();
                    });
                }
            }
            group.leave();
        }
        self.devicesQueue.async {
            self.devices[jid] = knownActiveDevices;
            self.activeDevicesPublisher.send(AvailabilityChanged(jid: jid, activeDevices: knownActiveDevices));
        }
    }

    func publishDeviceBundleIfNeeded(completionHandler: (()->Void)?) {
        guard let pepJid = context?.userBareJid, let pubsubModule = context?.module(.pubsub) else {
            return;
        }
        
        pubsubModule.retrieveItems(from: pepJid, for: bundleNode(for: storage.identityKeyStore.localRegistrationId()), limit: .items(withIds: ["current"]), completionHandler: { result in
            switch result {
            case .success(let items):
                self.publishDeviceBundle(currentBundle: items.items.first?.payload, completionHandler: completionHandler);
            case .failure(let error):
                guard error.condition == .item_not_found || error.condition == .internal_server_error else {
                    return;
                }
                self.publishDeviceBundle(currentBundle: nil, completionHandler: completionHandler);
            }
        });
    }
    
    public func removeDevices(withIds: [Int32]) {
        guard let pepJid = context?.userBareJid, let pubsubModule = context?.module(.pubsub) else {
            return;
        }
        
        let ids = withIds.map { (deviceId) -> UInt32 in
            return UInt32(bitPattern: deviceId);
        }
        
        withIds.forEach { deviceId in
            _ = self.storage.identityKeyStore.setStatus(active: false, forIdentity: SignalAddress(name: pepJid.description, deviceId: deviceId));
            
            pubsubModule.deleteNode(from: pepJid, node: bundleNode(for: UInt32(bitPattern: deviceId)), completionHandler: { _ in });
        }
        
        self.publishDeviceIdIfNeeded(removeDevicesWithIds: ids);
    }
    
    private var postponedSessions: [BareJID?:[SignalAddress]] = [:];
    private var postponedHealing: [BareJID?:[SignalAddress]] = [:];
    
    private func postponeSession(for jid: BareJID?, address: SignalAddress) -> Bool {
        return devicesQueue.sync {
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
    }
    
    private func postponeHealing(for jid: BareJID?, address: SignalAddress) -> Bool {
        return devicesQueue.sync {
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
    }
    
    private func processPostponed(for jid: BareJID?) {
        if let sessions = postponedSessions.removeValue(forKey: jid) {
            if !sessions.isEmpty {
                if self.storage.preKeyStore.flushDeletedPreKeys() {
                    self.publishDeviceBundleIfNeeded(completionHandler: nil);
                }
            }
            
            for address in sessions {
                self.completeSession(forAddress: address);
            }
        }
        if let healings = postponedHealing.removeValue(forKey: jid) {
            for healing in healings {
                self.buildSession(forAddress: healing, completionHandler: {
                    self.completeSession(forAddress: healing);
                })
            }
        }
    }
    
    fileprivate func signedPreKey(regenerate: Bool = false) -> SignalSignedPreKey? {
        let signedPreKeyId = storage.signedPreKeyStore.countSignedPreKeys();
        var signedPreKey: SignalSignedPreKey? = nil;
        if (!regenerate) && (signedPreKeyId != 0) {
            if let data = signalContext.storage.signedPreKeyStore.loadSignedPreKey(withId: UInt32(signedPreKeyId)) {
                signedPreKey = SignalSignedPreKey(fromSerializedData: data);
            }
        }
        
        if signedPreKey == nil {
            let identityKeyPair = storage.identityKeyStore.keyPair()!;
            print("regenerating signed pre key!");
            signedPreKey = signalContext.generateSignedPreKey(withIdentity: identityKeyPair, signedPreKeyId: UInt32(signedPreKeyId + 1))
            guard signedPreKey != nil else {
                return nil;
            }
            guard signalContext.storage.signedPreKeyStore.storeSignedPreKey(signedPreKey!.serializedData!, withId: signedPreKey!.preKeyId) else {
                return nil;
            }
        }
        return signedPreKey;
    }
    
//    fileprivate func publishDeviceBundleNoKeys(regenerate: Bool = false, completionHandler: @escaping ()->Void) {
//        if let signedPreKey = signedPreKey(regenerate: regenerate) {
//            let preKeys = signalContext.generatePreKeys(withStartingPreKeyId: 0, count: 20);
//            preKeys.forEach { (preKey) in
//                _ = self.storage.preKeyStore.storePreKey(preKey.serializedData!, withId: preKey.preKeyId);
//            }
//            publishDeviceBundle(signedPreKey: signedPreKey, preKeys: preKeys, completionHandler: completionHandler);
//        }
//    }

    fileprivate func publishDeviceBundle(currentBundle: Element?, completionHandler: (()->Void)?) {
        guard let identityPublicKey = storage.identityKeyStore.keyPair()?.publicKey?.base64EncodedString() else {
            completionHandler?();
            return;
        }

        var flush: Bool = currentBundle == nil;
        if !flush {
            flush = identityPublicKey != currentBundle?.firstChild(name: "identityKey")?.value;
        }
        
        if let signedPreKey = self.signedPreKey(regenerate: flush), let signedPreKeyBase64 = signedPreKey.publicKeyData?.base64EncodedString() {
            let signatureBase64 = signedPreKey.signature.base64EncodedString();
            var changed = flush || signedPreKeyBase64 != currentBundle?.firstChild(name: "signedPreKeyPublic")?.value || signatureBase64 != currentBundle?.firstChild(name: "signedPreKeySignature")?.value;
            
            let currentKeys = currentBundle?.firstChild(name: "prekeys")?.compactMapChildren({ preKeyEl -> UInt32? in
                guard let preKeyId = preKeyEl.attribute("preKeyId") else {
                    return nil;
                }
                return UInt32(preKeyId);
            });
            
            var validKeys = currentKeys?.map({ (preKeyId) -> SignalPreKey? in
                guard let key = self.storage.preKeyStore.loadPreKey(withId: preKeyId) else {
                    return nil;
                }
                return SignalPreKey(fromSerializedData: key);
            }).filter({ (preKey) -> Bool in
                return preKey != nil;
            }).map({ preKey -> SignalPreKey in
                return preKey!;
            }) ?? [];
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
                publishDeviceBundle(signedPreKey: signedPreKey, preKeys: validKeys, completionHandler: completionHandler);
            } else {
                completionHandler?();
            }
        }
    }

    func publishDeviceBundle(signedPreKey: SignalSignedPreKey, preKeys: [SignalPreKey], completionHandler: (()->Void)?) {
        let identityKeyPair = storage.identityKeyStore.keyPair()!;
        
        let bundleEl = Element(name: "bundle", xmlns: OMEMOModule.XMLNS);
        bundleEl.addChild(Element(name: "signedPreKeyPublic", cdata: signedPreKey.publicKeyData!.base64EncodedString(), attributes: ["signedPreKeyId": String(signedPreKey.preKeyId)]));
        bundleEl.addChild(Element(name: "signedPreKeySignature", cdata: signedPreKey.signature.base64EncodedString()));
        bundleEl.addChild(Element(name: "identityKey", cdata: identityKeyPair.publicKey!.base64EncodedString()));
        let preKeysElems = preKeys.map({ (preKey) -> Element in
            return Element(name: "preKeyPublic", cdata: preKey.serializedPublicKey!.base64EncodedString(), attributes: ["preKeyId": String(preKey.preKeyId)]);
        });
        bundleEl.addChild(Element(name: "prekeys", children: preKeysElems));
        
        let publishOptions = PubSubNodeConfig();
        publishOptions.accessModel = .open;
        
        guard let pubsubModule = context?.module(.pubsub) else {
            return;
        }
        pubsubModule.publishItem(at: nil, to: bundleNode(for: storage.identityKeyStore.localRegistrationId()), itemId: "current", payload: bundleEl, publishOptions: publishOptions, completionHandler: { result in
            switch result {
            case .success(_):
                print("published public keys!");
                completionHandler?();
            case .failure(let pubsubError):
                print("cound not publish keys:", pubsubError);
            }
        });
    }
    
    private func completeSession(forAddress address: SignalAddress) {
        let message = Message()
        message.type = .chat;
        message.to = JID(address.name);
        let result = self._encode(message: message, for: [address], forSelf: false);
        switch result {
        case .successMessage(let message, _):
            message.hints = [.store];
            self.write(stanza: message);
        case .failure(let error):
            print("failed to complete session for address: \(address), error: \(error)");
        }
    }
    
    open func buildSession(forAddress address: SignalAddress, completionHandler: (()->Void)? = nil) {
        let pepJid = BareJID(address.name);
        guard let pubsubModule: PubSubModule = context?.module(.pubsub) else {
            return;
        }
        pubsubModule.retrieveItems(from: pepJid, for: bundleNode(for: UInt32(bitPattern: address.deviceId)), limit: .lastItems(1), completionHandler: { result in
            switch result {
            case .success(let items):
                guard let bundle = OMEMOBundle(from: items.items.first?.payload) else {
                    print("could not create a bundle!");
                    self.markDeviceAsFailed(for: pepJid, andDeviceId: address.deviceId);
                    completionHandler?();
                    return;
                }
                
                let preKey = bundle.preKeys[Int.random(in: 0..<bundle.preKeys.count)];
                if let preKeyBundle = SignalPreKeyBundle(registrationId: 0, deviceId: address.deviceId, preKey: preKey, bundle: bundle) {
                    if let builder = SignalSessionBuilder(withAddress: address, andContext: self.signalContext) {
                        if builder.processPreKeyBundle(bundle: preKeyBundle) {
                            print("signal session established!");
                        } else {
                            print("building session failed!");
                        }
                    } else {
                        print("unable to create builder!");
                    }
                } else {
                    print("unable to create pre key bundle!");
                    self.markDeviceAsFailed(for: pepJid, andDeviceId: address.deviceId);
                }
                completionHandler?();
            case .failure(let error):
                if let account = self.context?.userBareJid, error.condition == .item_not_found, account == pepJid {
                    // there is not bundle for local device-id
                    self.devicesQueue.async {
                        self.ownBrokenDevices.append(address.deviceId);
                    }
                } else {
                    self.markDeviceAsFailed(for: pepJid, andDeviceId: address.deviceId);
                    completionHandler?();
                }
            }
        });
    }
    
    fileprivate func markDeviceAsFailed(for jid: BareJID, andDeviceId deviceId: Int32) {
        var devices = self.devicesFetchError[jid] ?? [];
        if !devices.contains(deviceId) {
            devices.append(deviceId);
            self.devicesFetchError[jid] = devices;
        }
    }
    
    func bundleNode(for deviceId: UInt32) -> String {
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
    
    open class OMEMOPreKey {
        
        public let preKeyId: UInt32;
        public let data: Data;
        
        public convenience init?(from: Element) {
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

public enum EncryptionResult<Success, Failure> {
    case successMessage(_ success: Success, fingerprint: String?)
    case failure(_ error: Failure)
}

public enum DecryptionResult<Success, Failure> {
    case successMessage(_ success: Success, fingerprint: String?)
    case successTransportKey(_ key: Data, iv: Data)
    case failure(_ error: Failure)
}
