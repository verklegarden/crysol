// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256r1Offchain} from "src/offchain/secp256r1/Secp256r1Offchain.sol";
import {
    Secp256r1,
    SecretKey,
    PublicKey
} from "src/onchain/secp256r1/Secp256r1.sol";
import {
    Secp256r1Arithmetic,
    Point,
    ProjectivePoint
} from "src/onchain/secp256r1/Secp256r1Arithmetic.sol";

/**
 * @notice Secp256r1Arithmetic Unit Tests
 */
contract Secp256r1ArithmeticTest is Test {
    using Secp256r1Offchain for SecretKey;
    using Secp256r1 for SecretKey;
    using Secp256r1 for PublicKey;
    using Secp256r1 for Point;
    using Secp256r1Arithmetic for Point;
    using Secp256r1Arithmetic for ProjectivePoint;

    // Uncompressed Generator G.
    // Copied from [SEC-2 v2].
    bytes constant GENERATOR_ENCODED =
        hex"046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";

    // Compressed Generator G.
    // Copied from [SEC-2 v2].
    bytes constant GENERATOR_COMPRESSED_ENCODED =
        hex"036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";

    Secp256r1ArithmeticWrapper wrapper;

    function setUp() public {
        wrapper = new Secp256r1ArithmeticWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Constants

    function test_G() public {
        Point memory got = wrapper.G();
        Point memory want =
            Secp256r1Arithmetic.pointFromEncoded(GENERATOR_ENCODED);

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
        assertTrue(wrapper.isOnCurve(Secp256r1Arithmetic.Identity()));
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

    // -- eq

    function testFuzz_Point_eq(SecretKey sk1, SecretKey sk2) public {
        vm.assume(sk1.isValid());
        vm.assume(sk2.isValid());

        Point memory p1 = sk1.toPublicKey().intoPoint();
        Point memory p2 = sk2.toPublicKey().intoPoint();

        if (sk1.asUint() == sk2.asUint()) {
            assertTrue(wrapper.eq(p1, p2));
        } else {
            assertFalse(wrapper.eq(p1, p2));
        }
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

    function testFuzz_ProjectivePoint_add(SecretKey sk1, SecretKey sk2)
        public
    {
        vm.assume(sk1.isValid());
        vm.assume(sk2.isValid());

        // Compute secret key sum = sk1 + sk2 (mod Q).
        // Assume valid secret key.
        uint sumScalar = addmod(sk1.asUint(), sk2.asUint(), Secp256r1.Q);
        vm.assume(sumScalar != 0);
        console.log("sumScalar", sumScalar);
        SecretKey sum = Secp256r1.secretKeyFromUint(sumScalar);

        // Compute want = [sum]G.
        Point memory want = sum.toPublicKey().intoPoint();

        // Compute got = [sk1]G + [sk2]G.
        ProjectivePoint memory left =
            Secp256r1.G().toProjectivePoint().mul(sk1.asUint());
        ProjectivePoint memory right =
            Secp256r1.G().toProjectivePoint().mul(sk2.asUint());
        Point memory got = left.add(right).intoPoint();

        assertTrue(want.eq(got));
    }

    // TODO: Need r1 add() test vectors.

    function test_ProjectivePoint_add_Identity() public {
        ProjectivePoint memory g = Secp256r1Arithmetic.G().toProjectivePoint();
        ProjectivePoint memory id = Secp256r1Arithmetic.ProjectiveIdentity();
        Point memory got;

        // Test id + g.
        got = wrapper.add(id, g).intoPoint();
        assertTrue(got.eq(Secp256r1Arithmetic.G()));
        // Test g + id.
        got = wrapper.add(g, id).intoPoint();
        assertTrue(got.eq(Secp256r1Arithmetic.G()));
    }

    function test_ProjectivePoint_add_UpToIdentity() public {
        // Note that 1 + Q-1 = Q and [Q]G = Identity().
        SecretKey sk1 = Secp256r1.secretKeyFromUint(1);
        SecretKey sk2 = Secp256r1.secretKeyFromUint(Secp256r1.Q - 1);

        ProjectivePoint memory p1 = sk1.toPublicKey().toProjectivePoint();
        ProjectivePoint memory p2 = sk2.toPublicKey().toProjectivePoint();

        ProjectivePoint memory sum = wrapper.add(p1, p2);

        assertTrue(sum.isIdentity());
        assertTrue(sum.intoPoint().isIdentity());
    }

    // -- mul

    // TODO: secp256r1 mul() test useless if offchain not using vm.
    function testFuzz_ProjectivePoint_mul(SecretKey sk) public {
        vm.assume(sk.isValid());

        ProjectivePoint memory g = Secp256r1Arithmetic.G().toProjectivePoint();

        Point memory got = wrapper.mul(g, sk.asUint()).intoPoint();
        Point memory want = sk.toPublicKey().intoPoint();

        assertTrue(want.eq(got));
    }

    // TODO: Need r1 mul() test vectors.

    function testFuzz_ProjectivePoint_mul_ReturnsIdentityIfScalarIsZero(
        ProjectivePoint memory point
    ) public {
        assertTrue(wrapper.mul(point, 0).isIdentity());
    }

    function testFuzz_ProjectivePoint_mul_ReturnsIdentityIfPointIsIdentity(
        SecretKey sk
    ) public {
        vm.assume(sk.isValid());

        ProjectivePoint memory id = Secp256r1Arithmetic.ProjectiveIdentity();
        assertTrue(wrapper.mul(id, sk.asUint()).isIdentity());
    }

    function testFuzz_ProjectivePoint_mul_RevertsIf_ScalarNotFelt(
        ProjectivePoint memory point,
        uint scalar
    ) public {
        vm.assume(scalar >= Secp256r1Arithmetic.Q);

        vm.expectRevert("ScalarMustBeFelt()");
        wrapper.mul(point, scalar);
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
        Point memory identity = Secp256r1Arithmetic.Identity();

        assertTrue(wrapper.toProjectivePoint(identity).isIdentity());
    }

    //----------------------------------
    // Projective Point

    // -- intoPoint

    // TODO: Test no new memory allocation.
    function testFuzz_ProjectivePoint_intoPoint(SecretKey a, SecretKey b)
        public
    {
        vm.assume(a.isValid());
        vm.assume(b.isValid());

        // To produce random ProjectivePoints with non-zero z coordinate, add
        // two random points via ProjectivePoint::add().

        // Compute [a+b]G.
        uint scalar = addmod(a.asUint(), b.asUint(), Secp256r1.Q);
        Point memory want =
            Secp256r1.secretKeyFromUint(scalar).toPublicKey().intoPoint();

        // Compute [a]G + [b]G via ProjectivePoints.
        // forgefmt: disable-next-item
        ProjectivePoint memory sum = a.toPublicKey().toProjectivePoint()
                                      .add(b.toPublicKey().toProjectivePoint());

        Point memory got = wrapper.intoPoint(sum);

        assertTrue(want.eq(got));
    }

    function test_ProjectivePoint_intoPoint_Identity() public {
        ProjectivePoint memory identity =
            Secp256r1Arithmetic.ProjectiveIdentity();

        assertTrue(wrapper.intoPoint(identity).isIdentity());
    }

    // -- toPoint

    function test_ProjectivePoint_toPoint(SecretKey a, SecretKey b) public {
        vm.assume(a.isValid());
        vm.assume(b.isValid());

        // To produce random ProjectivePoints with non-zero z coordinate, add
        // two random points via ProjectivePoint::add().

        // Compute [a+b]G.
        uint scalar = addmod(a.asUint(), b.asUint(), Secp256r1.Q);
        Point memory want =
            Secp256r1.secretKeyFromUint(scalar).toPublicKey().intoPoint();

        // Compute [a]G + [b]G via ProjectivePoints.
        // forgefmt: disable-next-item
        ProjectivePoint memory sum = a.toPublicKey().toProjectivePoint()
                                      .add(b.toPublicKey().toProjectivePoint());

        Point memory got = wrapper.toPoint(sum);

        assertTrue(want.eq(got));
    }

    function test_ProjectivePoint_toPoint_Identity() public {
        ProjectivePoint memory identity =
            Secp256r1Arithmetic.ProjectiveIdentity();

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
        assertTrue(point.eq(Secp256r1Arithmetic.G()));

        // TODO: Find r1 point to test encoding.
        //blob = hex"";
        //point = wrapper.pointFromEncoded(blob);
        //assertTrue(
        //    point.eq(
        //        Point({
        //            x: uint(),
        //            y: uint()
        //        })
        //    )
        //);
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
        point = Secp256r1Arithmetic.G();
        blob = wrapper.toEncoded(point);
        assertEq(blob, GENERATOR_ENCODED);

        // TODO: Find r1 point to test encoding.
        // Some other point, ie [2]G.
        //point = Point({
        //    x: uint(),
        //    y: uint()
        //});
        //blob = wrapper.toEncoded(point);
        //assertEq(
        //    blob,
        //    hex""
        //);
    }

    function test_Point_toEncoded_Identity() public {
        Point memory point = Secp256r1Arithmetic.Identity();
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
        assertTrue(point.eq(Secp256r1Arithmetic.G()));
    }

    function test_Point_pointFromCompressedEncoded_IfyParityEven() public {
        SecretKey sk = Secp256r1.secretKeyFromUint(4);
        Point memory point = sk.toPublicKey().intoPoint();
        assert(point.yParity() == 0);

        Point memory got =
            wrapper.pointFromCompressedEncoded(point.toCompressedEncoded());
        assertTrue(point.eq(got));
    }

    function test_Point_pointFromCompressedEncoded_IfyParityOdd() public {
        SecretKey sk = Secp256r1.secretKeyFromUint(2);
        Point memory point = sk.toPublicKey().intoPoint();
        assert(point.yParity() == 1);

        Point memory got =
            wrapper.pointFromCompressedEncoded(point.toCompressedEncoded());
        assertTrue(point.eq(got));
    }

    function test_Point_pointFromCompressedEncoded_Identity() public {
        Point memory id = Secp256r1Arithmetic.Identity();

        Point memory got =
            wrapper.pointFromCompressedEncoded(id.toCompressedEncoded());
        assertTrue(got.isIdentity());
    }

    function test_Point_pointFromCompressedEncoded_RevertsIf_IdentityNot1ByteEncoded(
    ) public {
        bytes memory blob;

        // Using 0x02 prefix.
        blob = abi.encodePacked(bytes1(0x02), uint(0));
        vm.expectRevert("PointNotOnCurve()");
        wrapper.pointFromCompressedEncoded(blob);

        // Using 0x03 prefix.
        blob = abi.encodePacked(bytes1(0x03), uint(0));
        vm.expectRevert("PointNotOnCurve()");
        wrapper.pointFromCompressedEncoded(blob);
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

    function testFuzz_Point_pointFromCompressedEncoded_RevertsIf_PointNotOnCurve(
        Point memory point
    ) public {
        vm.skip(true);
        // TODO: Find secp256r1 x coordinates not on the curve for compressed
        //       byte encoding.
    }

    function test_Point_toCompressedEncoded_IfyParityEven() public {
        vm.skip(true);
        // TODO: Find r1 point to test encoding.
        // Some point, ie [2]G.
        //Point memory point = Point({
        //    x: uint(),
        //    y: uint()
        //});
        //bytes memory blob = wrapper.toCompressedEncoded(point);
        //
        //assertEq(
        //    blob,
        //    hex""
        //);
    }

    function test_Point_toCompressedEncoded_IfyParityOdd() public {
        vm.skip(true);
        // TODO: Find r1 point to test encoding.
        // Some point, ie [6]G.
        //Point memory point = Point({
        //    x: uint(),
        //    y: uint()
        //});
        //bytes memory blob = wrapper.toCompressedEncoded(point);
        //
        //assertEq(
        //    blob,
        //    hex""
        //);
    }

    function test_Point_toCompressedEncoded_Identity() public {
        Point memory point = Secp256r1Arithmetic.Identity();
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
contract Secp256r1ArithmeticWrapper {
    using Secp256r1Arithmetic for Point;
    using Secp256r1Arithmetic for ProjectivePoint;

    //--------------------------------------------------------------------------
    // Constants

    function G() public pure returns (Point memory) {
        return Secp256r1Arithmetic.G();
    }

    //--------------------------------------------------------------------------
    // Point

    function Identity() public pure returns (Point memory) {
        return Secp256r1Arithmetic.Identity();
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

    function eq(Point memory point, Point memory other)
        public
        pure
        returns (bool)
    {
        return point.eq(other);
    }

    //--------------------------------------------------------------------------
    // Projective Point

    function ProjectiveIdentity()
        public
        pure
        returns (ProjectivePoint memory)
    {
        return Secp256r1Arithmetic.ProjectiveIdentity();
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
        return Secp256r1Arithmetic.pointFromEncoded(blob);
    }

    function toEncoded(Point memory point) public pure returns (bytes memory) {
        return point.toEncoded();
    }

    function pointFromCompressedEncoded(bytes memory blob)
        public
        view
        returns (Point memory)
    {
        return Secp256r1Arithmetic.pointFromCompressedEncoded(blob);
    }

    function toCompressedEncoded(Point memory point)
        public
        pure
        returns (bytes memory)
    {
        return point.toCompressedEncoded();
    }
}
