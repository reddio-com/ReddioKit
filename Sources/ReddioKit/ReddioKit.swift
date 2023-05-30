//
//  ReddioKit.swift
//
//
//  Created by STRRL on 2023/5/29.
//

import Foundation
import ReddioCrypto

public let STRING_MAX_SIZE = 65

public func sign(privateKey: String, msgHash: String, seed: String?) throws -> Signature {
    var signDocument = ReddioCrypto.SignDocument(
        private_key: (privateKey as NSString).utf8String,
        msg_hash: (msgHash as NSString).utf8String,
        seed: nil
    )

    if seed != Optional.none {
        signDocument.seed = (seed! as NSString).utf8String
    }
    let r = UnsafeMutablePointer<CChar>.allocate(capacity: STRING_MAX_SIZE)
    defer { r.deallocate() }
    let s = UnsafeMutablePointer<CChar>.allocate(capacity: STRING_MAX_SIZE)
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
    let out = UnsafeMutablePointer<CChar>.allocate(capacity: STRING_MAX_SIZE)
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

    let out = UnsafeMutablePointer<CChar>.allocate(capacity: STRING_MAX_SIZE)
    defer { out.deallocate() }
    let errno = ReddioCrypto.get_transfer_msg_hash(transferMsg, out)
    if errno != ReddioCrypto.Ok {
        throw ReddioCryptoError.error(reason: String(cString: ReddioCrypto.explain(errno)))
    }

    return String(cString: out)
}

public func getLimitOrderMsgHashWithFee(
    vaultSell: Int64,
    vaultBuy: Int64,
    amountSell: Int64,
    amountBuy: Int64,
    tokenSell: String,
    tokenBuy: String,
    nonce: Int64,
    expirationTimestamp: Int64,
    feeToken: String,
    feeVaultId: Int64,
    feeLimit: Int64
) throws -> String {
    let limitOrderMsgWithFee = ReddioCrypto.LimitOrderMsgWithFee(
        vault_sell: (String(vaultSell) as NSString).utf8String,
        vault_buy: (String(vaultBuy) as NSString).utf8String,
        amount_sell: (String(amountSell) as NSString).utf8String,
        amount_buy: (String(amountBuy) as NSString).utf8String,
        token_sell: (tokenSell as NSString).utf8String,
        token_buy: (tokenBuy as NSString).utf8String,
        nonce: (String(nonce) as NSString).utf8String,
        expiration_time_stamp: (String(expirationTimestamp) as NSString).utf8String,
        fee_token: (feeToken as NSString).utf8String,
        fee_vault_id: (String(feeVaultId) as NSString).utf8String,
        fee_limit: (String(feeLimit) as NSString).utf8String
    )
    let out = UnsafeMutablePointer<CChar>.allocate(capacity: STRING_MAX_SIZE)
    defer { out.deallocate() }
    let errno = ReddioCrypto.get_limit_order_msg_hash_with_fee(limitOrderMsgWithFee, out)
    if errno != ReddioCrypto.Ok {
        throw ReddioCryptoError.error(reason: String(cString: ReddioCrypto.explain(errno)))
    }
    return String(cString: out)
}

public func getCancelOrderMsgHash(orderId: Int64) throws -> String {
    let cancelOrderMsg = ReddioCrypto.CancelOrderMsg(order_id: (String(orderId) as NSString).utf8String)
    let out = UnsafeMutablePointer<CChar>.allocate(capacity: STRING_MAX_SIZE)
    defer { out.deallocate() }
    let errno = ReddioCrypto.get_cancel_order_msg_hash(cancelOrderMsg, out)
    if errno != ReddioCrypto.Ok {
        throw ReddioCryptoError.error(reason: String(cString: ReddioCrypto.explain(errno)))
    }
    return String(cString: out)
}

public func getPrivateKeyFromEthSignature(ethSignature: String) throws -> String {
    let out = UnsafeMutablePointer<CChar>.allocate(capacity: STRING_MAX_SIZE)
    defer { out.deallocate() }
    let errno = ReddioCrypto.get_private_key_from_eth_signature((ethSignature as NSString).utf8String, out)
    if errno != ReddioCrypto.Ok {
        throw ReddioCryptoError.error(reason: String(cString: ReddioCrypto.explain(errno)))
    }
    return String(cString: out)
}

public func getRandomPrivateKey() throws -> String {
    let out = UnsafeMutablePointer<CChar>.allocate(capacity: STRING_MAX_SIZE)
    defer { out.deallocate() }
    let errno = ReddioCrypto.get_random_private_key(out)
    if errno != ReddioCrypto.Ok {
        throw ReddioCryptoError.error(reason: String(cString: ReddioCrypto.explain(errno)))
    }
    return String(cString: out)
}
