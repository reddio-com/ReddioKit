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

public func getTransferMsgHash(
    amount: Int64,
    nonce: Int64,
    senderVaultId: Int64,
    token: String,
    receiverVaultId: Int64,
    receiverPublicKey: String,
    expirationTimestamp: Int64,
    condition: String?
) throws -> String {
    var transferMsg = ReddioCrypto.TransferMsg(
        amount: (String(amount) as NSString).utf8String,
        nonce: (String(nonce) as NSString).utf8String,
        sender_vault_id: (String(senderVaultId) as NSString).utf8String,
        token: (token as NSString).utf8String,
        receiver_vault_id: (String(receiverVaultId) as NSString).utf8String,
        receiver_public_key: (receiverPublicKey as NSString).utf8String,
        expiration_time_stamp: (String(expirationTimestamp) as NSString).utf8String,
        condition: nil
    )
    if condition != Optional.none {
        transferMsg.condition = (condition! as NSString).utf8String
    }

    let out = UnsafeMutablePointer<CChar>.allocate(capacity: 65)
    defer { out.deallocate() }
    let errno = ReddioCrypto.get_transfer_msg_hash(transferMsg, out)
    if errno != ReddioCrypto.Ok {
        throw ReddioCryptoError.error(reason: String(cString: ReddioCrypto.explain(errno)))
    }

    return String(cString: out)
}
