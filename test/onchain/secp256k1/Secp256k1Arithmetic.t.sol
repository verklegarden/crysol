// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "src/offchain/secp256k1/Secp256k1Offchain.sol";
import {
    Secp256k1,
    SecretKey,
    PublicKey
} from "src/onchain/secp256k1/Secp256k1.sol";
import {
    Secp256k1Arithmetic,
    Point,
    ProjectivePoint
} from "src/onchain/secp256k1/Secp256k1Arithmetic.sol";

import {Secp256k1ArithmeticTestVectors} from
    "./test-vectors/Secp256k1ArithmeticTestVectors.sol";

/**
 * @notice Secp256k1Arithmetic Unit Tests
 */
contract Secp256k1ArithmeticTest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;
    using Secp256k1Arithmetic for Point;
    using Secp256k1Arithmetic for ProjectivePoint;

    // Uncompressed Generator G.
    // Copied from [SEC-2 v2].
    bytes constant GENERATOR_ENCODED =
        hex"0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

    // Compressed Generator G.
    // Copied from [SEC-2 v2].
    bytes constant GENERATOR_COMPRESSED_ENCODED =
        hex"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

    Secp256k1ArithmeticWrapper wrapper;

    function setUp() public {
        wrapper = new Secp256k1ArithmeticWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Constants

    function test_G() public {
        Point memory got = wrapper.G();
        Point memory want =
            Secp256k1Arithmetic.pointFromEncoded(GENERATOR_ENCODED);

        assertEq(got.x, want.x);
        assertEq(got.y, want.y);
    }

    //--------------------------------------------------------------------------
    // Test: Point

    // -- Identity

    function test_Identity() public {
        assertTrue(wrapper.Identity().isIdentity());
    }

    // -- isIdentity

    function testFuzz_Point_isIdentity(Point memory point) public {
        if (point.x == 0 && point.y == 0) {
            assertTrue(wrapper.isIdentity(point));
        } else {
            assertFalse(wrapper.isIdentity(point));
        }
    }

    // -- isOnCurve

    function testFuzz_Point_isOnCurve(SecretKey sk) public {
        vm.assume(sk.isValid());

        Point memory point = sk.toPublicKey().intoPoint();

        assertTrue(wrapper.isOnCurve(point));
    }

    function test_Point_isOnCurve_Identity() public {
        assertTrue(wrapper.isOnCurve(Secp256k1Arithmetic.Identity()));
    }

    function testFuzz_Point_isOnCurve_FailsIf_NotOnCurve(
        SecretKey sk,
        uint xMask,
        uint yMask
    ) public {
        vm.assume(sk.isValid());
        vm.assume(xMask != 0 || yMask != 0);

        Point memory point = sk.toPublicKey().intoPoint();

        // Mutate point.
        point.x ^= xMask;
        point.y ^= yMask;

        assertFalse(wrapper.isOnCurve(point));
    }

    // -- yParity

    function testFuzz_Point_yParity(uint x, uint y) public {
        // yParity is 0 if y is even and 1 if y is odd.
        uint want = y % 2 == 0 ? 0 : 1;
        uint got = wrapper.yParity(Point(x, y));

        assertEq(want, got);
    }

    //--------------------------------------------------------------------------
    // Test: Projective Point

    // -- ProjectiveIdentity

    function test_ProjectiveIdentity() public {
        assertTrue(wrapper.ProjectiveIdentity().isIdentity());
    }

    // -- isIdentity

    function testFuzz_ProjectivePoint_isIdentity(ProjectivePoint memory point)
        public
    {
        if (point.x == 0 && point.z == 0) {
            assertTrue(wrapper.isIdentity(point));
        } else {
            assertFalse(wrapper.isIdentity(point));
        }
    }

    // -- add

    function testVectors_ProjectivePoint_add() public {
        ProjectivePoint memory g = Secp256k1Arithmetic.G().toProjectivePoint();
        ProjectivePoint memory p = Secp256k1Arithmetic.ProjectiveIdentity();

        Point[] memory vectors = Secp256k1ArithmeticTestVectors.addVectors();

        for (uint i; i < vectors.length; i++) {
            p = wrapper.add(p, g);

            assertTrue(p.toPoint().eq(vectors[i]));
        }
    }

    function test_ProjectivePoint_add_Identity() public {
        ProjectivePoint memory g = Secp256k1Arithmetic.G().toProjectivePoint();
        ProjectivePoint memory id = Secp256k1Arithmetic.ProjectiveIdentity();
        Point memory got;

        // Test id + g.
        got = wrapper.add(id, g).intoPoint();
        assertTrue(got.eq(Secp256k1Arithmetic.G()));
        // Test g + id.
        got = wrapper.add(g, id).intoPoint();
        assertTrue(got.eq(Secp256k1Arithmetic.G()));
    }

    function test_ProjectivePoint_add_UpToIdentity() public {
        // Note that 1 + Q-1 = Q and [Q]G = Identity().
        SecretKey sk1 = Secp256k1.secretKeyFromUint(1);
        SecretKey sk2 = Secp256k1.secretKeyFromUint(Secp256k1.Q - 1);

        ProjectivePoint memory p1 = sk1.toPublicKey().toProjectivePoint();
        ProjectivePoint memory p2 = sk2.toPublicKey().toProjectivePoint();

        ProjectivePoint memory sum = wrapper.add(p1, p2);

        assertTrue(sum.isIdentity());
        assertTrue(sum.intoPoint().isIdentity());
    }

    // -- mul

    function testVectors_ProjectivePoint_mul() public {
        ProjectivePoint memory g = Secp256k1Arithmetic.G().toProjectivePoint();

        uint[] memory scalars;
        Point[] memory products;
        (scalars, products) = Secp256k1ArithmeticTestVectors.mulVectors();

        for (uint i; i < scalars.length; i++) {
            Point memory p = wrapper.mul(g, scalars[i]).intoPoint();

            assertTrue(p.eq(products[i]));
        }
    }

    function testFuzz_ProjectivePoint_mul(SecretKey sk) public {
        vm.assume(sk.isValid());

        ProjectivePoint memory g = Secp256k1Arithmetic.G().toProjectivePoint();

        Point memory got = wrapper.mul(g, sk.asUint()).intoPoint();
        Point memory want = sk.toPublicKey().intoPoint();

        assertTrue(want.eq(got));
    }

    function testFuzz_ProjectivePoint_mul_ReturnsIdentityIfScalarIsZero(
        ProjectivePoint memory point
    ) public {
        assertTrue(wrapper.mul(point, 0).isIdentity());
    }

    function testFuzz_ProjectivePoint_mul_ReturnsIdentityIfPointIsIdentity(
        SecretKey sk
    ) public {
        vm.assume(sk.isValid());

        ProjectivePoint memory id = Secp256k1Arithmetic.ProjectiveIdentity();
        assertTrue(wrapper.mul(id, sk.asUint()).isIdentity());
    }

    function testFuzz_ProjectivePoint_mul_RevertsIf_ScalarNotFelt(
        ProjectivePoint memory point,
        uint scalar
    ) public {
        vm.assume(scalar >= Secp256k1Arithmetic.Q);

        vm.expectRevert("ScalarMustBeFelt()");
        wrapper.mul(point, scalar);
    }

    // -- mulToAddress

    function testFuzz_ProjectivePoint_mulToAddress(
        SecretKey sk,
        uint scalarSeed
    ) public {
        vm.assume(sk.isValid());

        Point memory point = sk.toPublicKey().intoPoint();
        uint scalar = _bound(scalarSeed, 1, Secp256k1Arithmetic.Q - 1);

        address got = wrapper.mulToAddress(point, scalar);
        // forgefmt: disable-next-item
        address want = point.toProjectivePoint()
                            .mul(scalar)
                            .intoPoint()
                            .intoPublicKey()
                            .toAddress();

        assertEq(got, want);
    }

    function testFuzz_ProjectivePoint_mulToAddress_ReturnsIdentityIfScalarIsZero(
        Point memory point
    ) public {
        assertEq(
            wrapper.mulToAddress(point, 0),
            Secp256k1Arithmetic.Identity().intoPublicKey().toAddress()
        );
    }

    function testFuzz_ProjectivePoint_mulToAddress_RevertsIf_ScalarNotFelt(
        Point memory point,
        uint scalar
    ) public {
        vm.assume(scalar >= Secp256k1Arithmetic.Q);

        vm.expectRevert("ScalarMustBeFelt()");
        wrapper.mulToAddress(point, scalar);
    }

    //--------------------------------------------------------------------------
    // Type Conversions

    //----------------------------------
    // Point

    // -- toProjectivePoint

    function testFuzz_Point_toProjectivePoint(SecretKey sk) public {
        vm.assume(sk.isValid());

        Point memory want = sk.toPublicKey().intoPoint();
        Point memory got = wrapper.toProjectivePoint(want).intoPoint();

        assertTrue(want.eq(got));
    }

    function test_Point_toProjectivePoint_Identity() public {
        Point memory identity = Secp256k1Arithmetic.Identity();

        assertTrue(wrapper.toProjectivePoint(identity).isIdentity());
    }

    //----------------------------------
    // Projective Point

    // -- intoPoint

    // TODO: Test no new memory allocation.
    // TODO: Not a real test. Use vectors from Paul Miller.
    function testFuzz_ProjectivePoint_intoPoint(SecretKey sk) public {
        vm.assume(sk.isValid());

        Point memory want = sk.toPublicKey().intoPoint();
        Point memory got = wrapper.intoPoint(want.toProjectivePoint());

        assertTrue(want.eq(got));
    }

    function test_ProjectivePoint_intoPoint_Identity() public {
        ProjectivePoint memory identity =
            Secp256k1Arithmetic.ProjectiveIdentity();

        assertTrue(wrapper.intoPoint(identity).isIdentity());
    }

    // -- toPoint

    // TODO: Not a real test. Use vectors from Paul Miller.
    function test_ProjectivePoint_toPoint(SecretKey sk) public {
        vm.assume(sk.isValid());

        Point memory want = sk.toPublicKey().intoPoint();
        Point memory got = wrapper.toPoint(want.toProjectivePoint());

        assertTrue(want.eq(got));
    }

    function test_ProjectivePoint_toPoint_Identity() public {
        ProjectivePoint memory identity =
            Secp256k1Arithmetic.ProjectiveIdentity();

        assertTrue(wrapper.toPoint(identity).isIdentity());
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    // -- Point <-> Encoded

    function test_pointFromEncoded() public {
        bytes memory blob;
        Point memory point;

        // Generator.
        blob = GENERATOR_ENCODED;
        point = wrapper.pointFromEncoded(blob);
        assertTrue(point.eq(Secp256k1Arithmetic.G()));

        // Some other point, ie [2]G.
        blob =
            hex"04C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE51AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A";
        point = wrapper.pointFromEncoded(blob);
        assertTrue(
            point.eq(
                Point({
                    x: uint(
                        0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
                    ),
                    y: uint(
                        0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A
                    )
                })
            )
        );
    }

    function test_pointFromEncoded_Identity() public {
        bytes memory blob = hex"00";
        Point memory point;

        point = wrapper.pointFromEncoded(blob);
        assertTrue(point.isIdentity());
    }

    function testFuzz_pointFromEncoded_RevertsIf_LengthNot65BytesAndNotIdentity(
        bytes memory blob
    ) public {
        vm.assume(blob.length != 65);
        vm.assume(blob.length != 1 && bytes1(blob) != bytes1(0x00));

        vm.expectRevert("LengthInvalid()");
        wrapper.pointFromEncoded(blob);
    }

    function testFuzz_pointFromEncoded_RevertsIf_PrefixNot04AndNotIdentity(
        bytes1 prefix,
        Point memory point
    ) public {
        vm.assume(prefix != bytes1(0x04));

        bytes memory blob = abi.encodePacked(prefix, point.x, point.y);

        vm.expectRevert("PrefixInvalid()");
        wrapper.pointFromEncoded(blob);
    }

    function testFuzz_pointFromEncoded_RevertsIf_DeserializedPointNotOnCurve(
        Point memory point
    ) public {
        vm.assume(!point.isOnCurve());

        bytes memory blob = abi.encodePacked(bytes1(0x04), point.x, point.y);

        vm.expectRevert("PointNotOnCurve()");
        wrapper.pointFromEncoded(blob);
    }

    function test_Point_toEncoded() public {
        Point memory point;
        bytes memory blob;

        // Generator.
        point = Secp256k1Arithmetic.G();
        blob = wrapper.toEncoded(point);
        assertEq(blob, GENERATOR_ENCODED);

        // Some other point, ie [2]G.
        point = Point({
            x: uint(
                0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
            ),
            y: uint(
                0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A
            )
        });
        blob = wrapper.toEncoded(point);
        assertEq(
            blob,
            hex"04C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE51AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"
        );
    }

    function test_Point_toEncoded_Identity() public {
        Point memory point = Secp256k1Arithmetic.Identity();
        bytes memory blob = wrapper.toEncoded(point);

        assertEq(blob, hex"00");
    }

    function testFuzz_Point_toEncoded_RevertsIf_PointNotOnCurve(
        Point memory point
    ) public {
        vm.assume(!point.isOnCurve());

        vm.expectRevert("PointNotOnCurve()");
        wrapper.toEncoded(point);
    }

    // -- Point <-> CompressedEncoded

    function test_Point_pointFromCompressedEncoded() public {
        bytes memory blob;
        Point memory point;

        // Generator.
        blob = GENERATOR_COMPRESSED_ENCODED;
        point = wrapper.pointFromCompressedEncoded(blob);
        assertTrue(point.eq(Secp256k1Arithmetic.G()));
    }

    function test_Point_pointFromCompressedEncoded_IfyParityEven() public {
        SecretKey sk = Secp256k1.secretKeyFromUint(2);
        Point memory point = sk.toPublicKey().intoPoint();
        assert(point.yParity() == 0);

        Point memory got =
            wrapper.pointFromCompressedEncoded(point.toCompressedEncoded());
        assertTrue(point.eq(got));
    }

    function test_Point_pointFromCompressedEncoded_IfyParityOdd() public {
        SecretKey sk = Secp256k1.secretKeyFromUint(6);
        Point memory point = sk.toPublicKey().intoPoint();
        assert(point.yParity() == 1);

        Point memory got =
            wrapper.pointFromCompressedEncoded(point.toCompressedEncoded());
        assertTrue(point.eq(got));
    }

    function test_Point_pointFromCompressedEncoded_Identity() public {
        Point memory id = Secp256k1Arithmetic.Identity();

        Point memory got =
            wrapper.pointFromCompressedEncoded(id.toCompressedEncoded());
        assertTrue(got.isIdentity());
    }

    function test_Point_pointFromCompressedEncoded_RevertsIf_LengthInvalid(
        bytes memory blob
    ) public {
        vm.assume(blob.length != 1 || bytes1(blob) != bytes1(0x00));
        vm.assume(blob.length != 33);

        vm.expectRevert("LengthInvalid()");
        wrapper.pointFromCompressedEncoded(blob);
    }

    function testFuzz_Point_pointFromCompressedEncoded_RevertsIf_PrefixInvalid(
        bytes1 prefix,
        uint x
    ) public {
        vm.assume(prefix != 0x02);
        vm.assume(prefix != 0x03);

        bytes memory blob = abi.encodePacked(prefix, x);

        vm.expectRevert("PrefixInvalid()");
        wrapper.pointFromCompressedEncoded(blob);
    }

    function test_Point_pointFromCompressedEncoded_RevertsIf_PointNotOnCurve()
        public
    {
        bytes memory blob = abi.encodePacked(bytes1(0x02), uint(0));

        vm.expectRevert("PointNotOnCurve()");
        wrapper.pointFromCompressedEncoded(blob);
    }

    function test_Point_toCompressedEncoded_IfyParityEven() public {
        // Some point, ie [2]G.
        Point memory point = Point({
            x: uint(
                0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
            ),
            y: uint(
                0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A
            )
        });
        bytes memory blob = wrapper.toCompressedEncoded(point);

        assertEq(
            blob,
            hex"02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"
        );
    }

    function test_Point_toCompressedEncoded_IfyParityOdd() public {
        // Some point, ie [6]G.
        Point memory point = Point({
            x: uint(
                0xFFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556
            ),
            y: uint(
                0xAE12777AACFBB620F3BE96017F45C560DE80F0F6518FE4A03C870C36B075F297
            )
        });
        bytes memory blob = wrapper.toCompressedEncoded(point);

        assertEq(
            blob,
            hex"03FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556"
        );
    }

    function test_Point_toCompressedEncoded_Identity() public {
        Point memory point = Secp256k1Arithmetic.Identity();
        bytes memory blob = wrapper.toCompressedEncoded(point);

        assertEq(blob, hex"00");
    }

    function testFuzz_Point_toCompressedEncoded_RevertsIf_PointNotOnCurve(
        Point memory point
    ) public {
        vm.assume(!point.isOnCurve());

        vm.expectRevert("PointNotOnCurve()");
        wrapper.toCompressedEncoded(point);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract Secp256k1ArithmeticWrapper {
    using Secp256k1Arithmetic for Point;
    using Secp256k1Arithmetic for ProjectivePoint;

    //--------------------------------------------------------------------------
    // Constants

    function G() public pure returns (Point memory) {
        return Secp256k1Arithmetic.G();
    }

    //--------------------------------------------------------------------------
    // Point

    function Identity() public pure returns (Point memory) {
        return Secp256k1Arithmetic.Identity();
    }

    function isIdentity(Point memory point) public pure returns (bool) {
        return point.isIdentity();
    }

    function isOnCurve(Point memory point) public pure returns (bool) {
        return point.isOnCurve();
    }

    function yParity(Point memory point) public pure returns (uint) {
        return point.yParity();
    }

    //--------------------------------------------------------------------------
    // Projective Point

    function ProjectiveIdentity()
        public
        pure
        returns (ProjectivePoint memory)
    {
        return Secp256k1Arithmetic.ProjectiveIdentity();
    }

    function isIdentity(ProjectivePoint memory point)
        public
        pure
        returns (bool)
    {
        return point.isIdentity();
    }

    function add(ProjectivePoint memory point, ProjectivePoint memory jOther)
        public
        pure
        returns (ProjectivePoint memory)
    {
        return point.add(jOther);
    }

    function mul(ProjectivePoint memory point, uint scalar)
        public
        pure
        returns (ProjectivePoint memory)
    {
        return point.mul(scalar);
    }

    function mulToAddress(Point memory point, uint scalar)
        public
        pure
        returns (address)
    {
        return point.mulToAddress(scalar);
    }

    //--------------------------------------------------------------------------
    // Type Conversions

    //----------------------------------
    // Point

    function toProjectivePoint(Point memory point)
        public
        pure
        returns (ProjectivePoint memory)
    {
        return point.toProjectivePoint();
    }

    //----------------------------------
    // Projective Point

    function intoPoint(ProjectivePoint memory point)
        public
        view
        returns (Point memory)
    {
        return point.intoPoint();
    }

    function toPoint(ProjectivePoint memory point)
        public
        view
        returns (Point memory)
    {
        return point.toPoint();
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    function pointFromEncoded(bytes memory blob)
        public
        pure
        returns (Point memory)
    {
        return Secp256k1Arithmetic.pointFromEncoded(blob);
    }

    function toEncoded(Point memory point) public pure returns (bytes memory) {
        return point.toEncoded();
    }

    function pointFromCompressedEncoded(bytes memory blob)
        public
        view
        returns (Point memory)
    {
        return Secp256k1Arithmetic.pointFromCompressedEncoded(blob);
    }

    function toCompressedEncoded(Point memory point)
        public
        pure
        returns (bytes memory)
    {
        return point.toCompressedEncoded();
    }
}
