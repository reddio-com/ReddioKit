import ReddioCrypto
@testable import ReddioKit
import XCTest

final class ReddioKitTests: XCTestCase {
    func testExplainError() {
        let cstring = ReddioCrypto.explain(ReddioCrypto.Ok)
        let result = String(cString: cstring!)
        XCTAssertEqual(result, "ok")
    }

    func testSign() throws {
        let result = try sign(
            privateKey: "3c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc",
            msgHash: "397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f",
            seed: nil
        )
        XCTAssertEqual(result.r, "173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882")
        XCTAssertEqual(result.s, "4b6d75385aed025aa222f28a0adc6d58db78ff17e51c3f59e259b131cd5a1cc")
    }

    func testVerify() throws {
        let result = try verify(
            publicKey: getPublicKey(
                privateKey: "3c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc"
            ),
            msgHash: "397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f",
            signature: Signature(
                r: "173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882",
                s: "4b6d75385aed025aa222f28a0adc6d58db78ff17e51c3f59e259b131cd5a1cc"
            )
        )
        XCTAssertTrue(result)
    }

    func testGetPublicKey() throws {
        let result = try getPublicKey(
            privateKey: "3c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc"
        )
        XCTAssertEqual(result, "77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43")
    }

    func testGetTransferMsgHash() throws {
        let result = try getTransferMsgHash(
            amount: 2_154_549_703_648_910_716,
            nonce: 1,
            senderVaultId: 34,
            token: "3003a65651d3b9fb2eff934a4416db301afd112a8492aaf8d7297fc87dcd9f4",
            receiverVaultId: 21,
            receiverPublicKey: "5fa3383597691ea9d827a79e1a4f0f7949435ced18ca9619de8ab97e661020",
            expirationTimestamp: 438_953,
            condition: nil
        )
        XCTAssertEqual(result, "6366b00c218fb4c8a8b142ca482145e8513c78e00faa0de76298ba14fc37ae7")
    }

    func testGetLimitOrderMsgHashWithFee() throws {
        let result = try getLimitOrderMsgHashWithFee(
            vaultSell: 21,
            vaultBuy: 27,
            amountSell: 2_154_686_749_748_910_716,
            amountBuy: 1_470_242_115_489_520_459,
            tokenSell: "5fa3383597691ea9d827a79e1a4f0f7989c35ced18ca9619de8ab97e661020",
            tokenBuy: "774961c824a3b0fb3d2965f01471c9c7734bf8dbde659e0c08dca2ef18d56a",
            nonce: 0,
            expirationTimestamp: 438_953,
            feeToken: "70bf591713d7cb7150523cf64add8d49fa6b61036bba9f596bd2af8e3bb86f9",
            feeVaultId: 593_128_169,
            feeLimit: 7
        )
        XCTAssertEqual(result, "2a6c0382404920ebd73c1cbc319cd38974e7e255e00394345e652b0ce2cefbd")
    }

    func testGetCancelOrderMsgHash() throws {
        let result = try getCancelOrderMsgHash(orderId: 233)
        XCTAssertEqual(result, "2d97ce4376a8cec568b243857eafd329fd90afca2437a3368f34884eed53fd3")
    }

    func testGetPrivateKeyFromEthSignature() throws {
        let result = try getPrivateKeyFromEthSignature(ethSignature: "21fbf0696d5e0aa2ef41a2b4ffb623bcaf070461d61cf7251c74161f82fec3a4370854bc0a34b3ab487c1bc021cd318c734c51ae29374f2beb0e6f2dd49b4bf41c")
        XCTAssertEqual(result, "766f11e90cd7c7b43085b56da35c781f8c067ac0d578eabdceebc4886435bda")
    }
}
