//
// SignalSessioBuilder.swift
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

open class SignalSessionBuilder {
    
    fileprivate let builder: OpaquePointer;
    fileprivate let address: SignalAddress;
    fileprivate let context: SignalContext;
    
    init?(withAddress addr: SignalAddress, andContext ctx: SignalContext) {
        var builder: OpaquePointer?;
        guard session_builder_create(&builder, ctx.storage.storeContext!, addr.address, ctx.globalContext) >= 0 && builder != nil else {
            return nil;
        }
        self.address = addr;
        self.context = ctx;
        self.builder = builder!;
    }
 
    deinit {
        session_builder_free(builder);
    }
    
    func processPreKeyBundle(bundle: SignalPreKeyBundle) -> Bool {
        guard session_builder_process_pre_key_bundle(builder, bundle.bundle) >= 0 else {
            return false;
        }
        return true;
    }
}
