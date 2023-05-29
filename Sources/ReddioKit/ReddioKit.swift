//
//  ReddioKit.swift
//
//
//  Created by STRRL on 2023/5/29.
//

import ReddioCrypto
import Foundation

public func sign(privateKey:String, msgHash:String, seed:String?)->Signature{
    var signDocument = ReddioCrypto.SignDocument(
        private_key: (privateKey as NSString).utf8String,
        msg_hash: (msgHash as NSString).utf8String,
        seed: nil
    )
    
    if seed != Optional.none {
        signDocument.seed = (seed! as NSString).utf8String
    }
    let r = UnsafeMutablePointer<CChar>.allocate(capacity: 65)
    defer {r.deallocate()}
    let s = UnsafeMutablePointer<CChar>.allocate(capacity: 65)
    defer {s.deallocate()}

    let result = ReddioCrypto.SignResult(r: r, s: s)
    let errno = ReddioCrypto.sign(signDocument,result)
    if errno != ReddioCrypto.Ok{
       
    }
    return Signature(r: String(cString: result.r), s:String(cString: result.s))
}
