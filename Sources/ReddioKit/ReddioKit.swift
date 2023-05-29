//
//  ReddioKit.swift
//
//
//  Created by STRRL on 2023/5/29.
//

import Foundation
import ReddioCrypto

public func sign(privateKey: String, msgHash: String, seed: String?) throws -> Signature {
    var signDocument = ReddioCrypto.SignDocument(
        private_key: (privateKey as NSString).utf8String,
        msg_hash: (msgHash as NSString).utf8String,
        seed: nil
    )

    if seed != Optional.none {
        signDocument.seed = (seed! as NSString).utf8String
    }
    let r = UnsafeMutablePointer<CChar>.allocate(capacity: 65)
    defer { r.deallocate() }
    let s = UnsafeMutablePointer<CChar>.allocate(capacity: 65)
    defer { s.deallocate() }

    let result = ReddioCrypto.SignResult(r: r, s: s)
    let errno = ReddioCrypto.sign(signDocument, result)
    if errno != ReddioCrypto.Ok {
        throw ReddioCryptoError.error(reason: String(cString: ReddioCrypto.explain(errno)))
    }
    return Signature(r: String(cString: result.r), s: String(cString: result.s))
}

public func verify(publicKey: String, msgHash: String, signature: Signature) throws -> Bool {
    let signature = ReddioCrypto.Signature(
        public_key: (publicKey as NSString).utf8String,
        msg_hash: (msgHash as NSString).utf8String,
        r: (signature.r as NSString).utf8String,
        s: (signature.s as NSString).utf8String
    )
    let out = UnsafeMutablePointer<Bool>.allocate(capacity: 1)
    defer { out.deallocate() }
    let errno = ReddioCrypto.verify(signature, out)
    if errno != ReddioCrypto.Ok {
        throw ReddioCryptoError.error(reason: String(cString: ReddioCrypto.explain(errno)))
    }
    return Bool(out[0])
}

public func getPublicKey(privateKey: String) throws -> String {
    let out = UnsafeMutablePointer<CChar>.allocate(capacity: 65)
    defer { out.deallocate() }
    let errno = ReddioCrypto.get_public_key((privateKey as NSString).utf8String, out)
    if errno != ReddioCrypto.Ok {
        throw ReddioCryptoError.error(reason: String(cString: ReddioCrypto.explain(errno)))
    }
    return String(cString: out)
}
