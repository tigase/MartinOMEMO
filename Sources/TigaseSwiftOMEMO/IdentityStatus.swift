//
// IdentityStatus.swift
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

public enum IdentityStatus: Int {
    case compromisedActive = -2
    case compromisedInactive = -1
    case undecidedActive = 0
    case undecidedInactive = 1
    case trustedActive = 2
    case trustedInactive = 3
    case verifiedActive = 4
    case verifiedInactive = 5
    
    public var trust: Trust {
        switch self {
        case .compromisedActive, .compromisedInactive:
            return .compromised;
        case .undecidedActive, .undecidedInactive:
            return .undecided;
        case .trustedActive, .trustedInactive:
            return .trusted;
        case .verifiedActive, .verifiedInactive:
            return .verified;
        }
    }
    
    public var isActive: Bool {
        switch self {
        case .compromisedActive, .undecidedActive, .trustedActive, .verifiedActive:
            return true;
        case .compromisedInactive, .undecidedInactive, .trustedInactive, .verifiedInactive:
            return false;
        }
    }
    
    public func toActive() -> IdentityStatus {
        guard !self.isActive else {
            return self;
        }
        
        return make(active: true, trust: self.trust);
    }
    
    public func toInactive() -> IdentityStatus {
        guard self.isActive else {
            return self;
        }

        return make(active: false, trust: self.trust);
    }
    
    public func toTrust(_ trust: Trust) -> IdentityStatus {
        return make(active: isActive, trust: trust);
    }
    
    public func make(active: Bool, trust: Trust) -> IdentityStatus {
        if active {
            switch trust {
            case .compromised:
                return .compromisedActive;
            case .undecided:
                return .undecidedActive;
            case .trusted:
                return .trustedActive;
            case .verified:
                return .verifiedActive;
            }
        } else {
            switch trust {
            case .compromised:
                return .compromisedInactive;
            case .undecided:
                return .undecidedInactive;
            case .trusted:
                return .trustedInactive;
            case .verified:
                return .verifiedInactive;
            }
        }
    }
}

public enum Trust {
    case compromised
    case undecided
    case trusted
    case verified
}
