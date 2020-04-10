//
// SignalCryptoProvider.swift
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
import CommonCrypto
import libsignal

public class SignalCryptoProvider {
    
    public fileprivate(set) var provider: signal_crypto_provider;
    
    init() {
        provider = signal_crypto_provider();
        provider.random_func = random_func;
        provider.hmac_sha256_init_func = hmac_sha256_init_func;
        provider.hmac_sha256_update_func = hmac_sha256_update_func;
        provider.hmac_sha256_final_func = hmac_sha256_final_func;
        provider.hmac_sha256_cleanup_func = hmac_sha256_cleanup_func;
        provider.sha512_digest_init_func = sha512_digest_init_func;
        provider.sha512_digest_update_func = sha512_digest_update_func;
        provider.sha512_digest_final_func = sha512_digest_final_func;
        provider.sha512_digest_cleanup_func = sha512_digest_cleanup_func;
        provider.encrypt_func = encrypt_func;
        provider.decrypt_func = decrypt_func;
        provider.user_data = SignalContext.bridge(self);
    }
}

fileprivate func random_func(data: UnsafeMutablePointer<UInt8>?, len: Int, ctx: UnsafeMutableRawPointer?) -> CInt {
    guard CCRandomGenerateBytes(data, len) == kCCSuccess else {
        return SG_ERR_INVAL;
    }
    return SG_SUCCESS;
}

fileprivate func hmac_sha256_init_func(hmacCtx: UnsafeMutablePointer<UnsafeMutableRawPointer?>?, key: UnsafePointer<UInt8>?, keyLen: Int, ctx: UnsafeMutableRawPointer?) -> CInt {
    guard hmacCtx != nil && key != nil else {
        return SG_ERR_INVAL;
    }
    
    guard let ctx: UnsafeMutablePointer<CCHmacContext> = malloc(MemoryLayout<CCHmacContext>.size)?.assumingMemoryBound(to: CCHmacContext.self) else {
        return SG_ERR_NOMEM;
    }
    
    CCHmacInit(ctx, CCHmacAlgorithm(kCCHmacAlgSHA256), key, keyLen);
    hmacCtx!.initialize(to: ctx);
    return SG_SUCCESS;
}

fileprivate func hmac_sha256_update_func(hmacCtx: UnsafeMutableRawPointer?, data: UnsafePointer<UInt8>?, dataLen: Int, ctx: UnsafeMutableRawPointer?) -> CInt {
    guard hmacCtx != nil && data != nil else {
        return SG_ERR_INVAL;
    }
    CCHmacUpdate(hmacCtx?.assumingMemoryBound(to: CCHmacContext.self), data!, dataLen);
    return SG_SUCCESS;
}

fileprivate func hmac_sha256_final_func(hmacCtx: UnsafeMutableRawPointer?, output: UnsafeMutablePointer<OpaquePointer?>?, ctx: UnsafeMutableRawPointer?) -> CInt {
    guard hmacCtx != nil && output != nil else {
        return SG_ERR_INVAL;
    }
    
    let length = Int(CC_SHA256_DIGEST_LENGTH);
    var data = Data(capacity: length);
    data.withUnsafeMutableBytes({ (ptr: UnsafeMutableRawBufferPointer) -> Void in
        CCHmacFinal(hmacCtx?.assumingMemoryBound(to: CCHmacContext.self), ptr.baseAddress)
        return;
    });
    output!.initialize(to: data.withUnsafeBytes({ (ptr: UnsafeRawBufferPointer) -> OpaquePointer in
        return signal_buffer_create(ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), length);
    }));
    return SG_SUCCESS;
}

fileprivate func hmac_sha256_cleanup_func(hmacCtx: UnsafeMutableRawPointer?, ctx: UnsafeMutableRawPointer?) {
    guard hmacCtx != nil else {
        return;
    }
    free(hmacCtx!);
}

fileprivate func sha512_digest_init_func(digestCtx: UnsafeMutablePointer<UnsafeMutableRawPointer?>?, ctx: UnsafeMutableRawPointer?) -> CInt {
    guard digestCtx != nil else {
        return SG_ERR_INVAL;
    }
    
    guard let ctx: UnsafeMutablePointer<CC_SHA512_CTX> = malloc(MemoryLayout<CC_SHA1_CTX>.size)?.assumingMemoryBound(to: CC_SHA512_CTX.self) else {
        return SG_ERR_NOMEM;
    }
    
    CC_SHA512_Init(ctx);
    digestCtx!.initialize(to: ctx);
    return SG_SUCCESS;
}

fileprivate func sha512_digest_update_func(digestCtx: UnsafeMutableRawPointer?, data: UnsafePointer<UInt8>?, dataLen: Int, ctx: UnsafeMutableRawPointer?) -> CInt {
    guard digestCtx != nil && data != nil else {
        return SG_ERR_INVAL;
    }
    CC_SHA512_Update(digestCtx!.assumingMemoryBound(to: CC_SHA512_CTX.self), data, UInt32(dataLen));
    return SG_SUCCESS;
}

fileprivate func sha512_digest_final_func(digestCtx: UnsafeMutableRawPointer?, output: UnsafeMutablePointer<OpaquePointer?>?, ctx: UnsafeMutableRawPointer?) -> CInt {
    guard digestCtx != nil && output != nil else {
        return SG_ERR_INVAL;
    }
    
    let length = Int(CC_SHA512_DIGEST_LENGTH);
    var data = Data(capacity: length);
    data.withUnsafeMutableBytes({ (ptr: UnsafeMutableRawBufferPointer) -> Void in
        CC_SHA512_Final(ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), digestCtx?.assumingMemoryBound(to: CC_SHA512_CTX.self))
        return;
    });
    output!.initialize(to: data.withUnsafeBytes({ (ptr: UnsafeRawBufferPointer) -> OpaquePointer in
        return signal_buffer_create(ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), length);
    }));
    return SG_SUCCESS;
}

fileprivate func sha512_digest_cleanup_func(digestCtx: UnsafeMutableRawPointer?, ctx: UnsafeMutableRawPointer?) {
    guard digestCtx != nil else {
        return;
    }
    free(digestCtx!);
}

fileprivate func encrypt_func(output: UnsafeMutablePointer<OpaquePointer?>?, cipher: CInt, key: UnsafePointer<UInt8>?, keyLen: Int, iv: UnsafePointer<UInt8>?, ivLen: Int, plaintext: UnsafePointer<UInt8>?, plaintextLen: Int, ctx: UnsafeMutableRawPointer?) -> CInt {
    guard cipher == SG_CIPHER_AES_CBC_PKCS5 else {
        return SG_ERR_INVAL;
    }
    
    var outLen: Int = 0;
    var bytes = Array(repeating: UInt8(0), count: kCCBlockSizeAES128 + plaintextLen);
    let result = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), key, keyLen, iv, plaintext, plaintextLen, &bytes, bytes.count, &outLen);
    guard result == kCCSuccess else {
        return SG_ERR_UNKNOWN;
    }
    
    output?.initialize(to: signal_buffer_create(&bytes, outLen));
    return SG_SUCCESS;
}

fileprivate func decrypt_func(output: UnsafeMutablePointer<OpaquePointer?>?, cipher: CInt, key: UnsafePointer<UInt8>?, keyLen: Int, iv: UnsafePointer<UInt8>?, ivLen: Int, ciphertext: UnsafePointer<UInt8>?, ciphertextLen: Int, ctx: UnsafeMutableRawPointer?) -> CInt {
    guard cipher == SG_CIPHER_AES_CBC_PKCS5 else {
        return SG_ERR_INVAL;
    }
    
    var outLen: Int = 0;
    var bytes = Array(repeating: UInt8(0), count: ciphertextLen + kCCBlockSizeAES128);
    guard CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), key, keyLen, iv, ciphertext, ciphertextLen, &bytes, bytes.count, &outLen) == kCCSuccess else {
        return SG_ERR_UNKNOWN;
    }
    
    output?.initialize(to: signal_buffer_create(&bytes, outLen));
    return SG_SUCCESS;
}
