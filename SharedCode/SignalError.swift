//
// SignalError.swift
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

public enum SignalError: Int, Error {
    
    // custom error code, not from libsignal but required for internal use to mark that message was not encrypted
    case notEncrypted = -100000;
    case noDestination = -100001;

    case noMemory = -12;
    case invalidArgument = -22;
    case unknown = -1000;
    case duplicateMessage = -1001;
    case invalidKey = -1002;
    case invalidKeyId = -1003;
    case invalidMac = -1004;
    case invalidMessage = -1005;
    case invalidVersion = -1006;
    case legacyMessage = -1007;
    case noSession = -1008;
    case staleKeyExchange = -1009;
    case unstrustedIdentity = -1010;
    case signatureVerificationFailed = -1011;
    case invalidProtoBuf = -1100;
    case fpInvalidVersion = -1200;
    case fpIdentityMismatch = -1201;

    public static func from(code: Int32) -> SignalError? {
        guard code < 0 else {
            return nil;
        }
        return SignalError(rawValue: Int(code)) ?? .unknown;
    }
}
