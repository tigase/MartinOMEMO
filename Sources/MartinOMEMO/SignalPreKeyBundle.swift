//
// SignalPreKeyBundle.swift
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

class SignalPreKeyBundle {
    
    let bundle: OpaquePointer;
    
    public init?(registrationId: UInt32, deviceId: Int32, preKey: OMEMOModule.OMEMOPreKey, bundle: OMEMOModule.OMEMOBundle) {
        guard let preKeyPublic = SignalIdentityKey.publicKey(from: preKey.data) else {
            return nil;
        }
        guard let signedPreKeyPublic = SignalIdentityKey.publicKey(from: bundle.signedPreKeyPublic) else {
            signal_type_unref(preKeyPublic);
            return nil;
        }
        guard let identityKey = SignalIdentityKey.publicKey(from: bundle.identityKey) else {
            signal_type_unref(preKeyPublic);
            signal_type_unref(signedPreKeyPublic);
            return nil;
        }
        
        var bundlePtr: OpaquePointer?;
        guard bundle.signature.withUnsafeBytes({ (bytes) -> Bool in
            let result = session_pre_key_bundle_create(&bundlePtr, registrationId, deviceId, preKey.preKeyId, preKeyPublic, bundle.signedPreKeyId, signedPreKeyPublic, bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bundle.signature.count, identityKey);
            signal_type_unref(preKeyPublic);
            signal_type_unref(signedPreKeyPublic);
            signal_type_unref(identityKey);
            
            return result >= 0;
        }) else {
            return nil;
        }
        
        // TODO: should we check validity? if so then we should do this here!
        
        self.bundle = bundlePtr!;
    }
 
    deinit {
        signal_type_unref(bundle);
    }
    
}
