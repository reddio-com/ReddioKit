@testable import ReddioKit
import XCTest

final class ReddioKitTests: XCTestCase {
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

    func testgetTransferMsgHash() throws {
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
}
