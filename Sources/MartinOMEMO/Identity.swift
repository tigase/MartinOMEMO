//
// Identity.swift
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

public class Identity {
    
    public let address: SignalAddress;
    public let status: IdentityStatus;
    public let fingerprint: String;
    public let key: Data;
    public let own: Bool;
    
    public init(address: SignalAddress, status: IdentityStatus, fingerprint: String, key: Data, own: Bool) {
        self.address = address;
        self.status = status;
        self.fingerprint = fingerprint;
        self.key = key;
        self.own = own;
    }
    
}
