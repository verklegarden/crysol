// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1Offchain} from "offchain/Secp256k1Offchain.sol";
import {Secp256k1, SecretKey, PublicKey} from "src/Secp256k1.sol";
import {Points, Point, ProjectivePoint} from "src/arithmetic/Points.sol";
import {Fp, Felt} from "src/arithmetic/Fp.sol";

import {PointsTestVectors} from "./test-vectors/PointsTestVectors.sol";

/**
 * @notice Points Unit Tests
 */
contract PointsTest is Test {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;
    using Points for Point;
    using Points for ProjectivePoint;
    using Fp for Felt;

    // Uncompressed Generator G.
    // Copied from [SEC-2 v2].
    bytes constant GENERATOR_ENCODED =
        hex"0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

    // Compressed Generator G.
    // Copied from [SEC-2 v2].
    bytes constant GENERATOR_COMPRESSED_ENCODED =
        hex"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

    PointsWrapper wrapper;

    function setUp() public {
        wrapper = new PointsWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Constants

    function test_G() public view {
        Point memory got = wrapper.G();
        Point memory want = Points.pointFromEncoded(GENERATOR_ENCODED);

        assertEq(got.x.asUint(), want.x.asUint());
        assertEq(got.y.asUint(), want.y.asUint());
    }

    //--------------------------------------------------------------------------
    // Test: Point

    // -- tryFromFelts

    function testFuzz_tryFromFelts(SecretKey sk) public {
        vm.assume(sk.isValid());

        PublicKey memory pk = sk.toPublicKey();

        Point memory want = pk.intoPoint();
        (Point memory got, bool ok) = wrapper.tryFromFelts(pk.x, pk.y);
        assertTrue(ok);
        assertTrue(want.eq(got));
    }

    function testFuzz_tryFromFelts_FailsIf_PointInvalid_XCoordinateInvalidFelt(uint xSeed, Felt y) public view {
        vm.assume(y.isValid());

        Felt x = Fp.unsafeFromUint(_bound(xSeed, Secp256k1.P, type(uint).max));

        (, bool ok) = wrapper.tryFromFelts(x, y);
        assertFalse(ok);
    }

    function testFuzz_tryFromFelts_FailsIf_PointInvalid_YCoordinateInvalidFelt(Felt x, uint ySeed) public view {
        vm.assume(x.isValid());

        Felt y = Fp.unsafeFromUint(_bound(ySeed, Secp256k1.P, type(uint).max));

        (, bool ok) = wrapper.tryFromFelts(x, y);
        assertFalse(ok);
    }

    function testFuzz_tryFromFelts_FailsIf_PointInvalid_NotOnCurve(Felt x, Felt y) public view {
        Point memory p = Point(x, y);
        vm.assume(!p.isOnCurve());

        (, bool ok) = wrapper.tryFromFelts(x, y);
        assertFalse(ok);
    }

    // -- fromFelts

    function testFuzz_fromFelts(SecretKey sk) public {
        vm.assume(sk.isValid());

        PublicKey memory pk = sk.toPublicKey();

        Point memory want = pk.intoPoint();
        Point memory got = wrapper.fromFelts(pk.x, pk.y);
        assertTrue(want.eq(got));
    }

    function testFuzz_fromFelts_RevertsIf_PointInvalid_XCoordinateInvalidFelt(uint xSeed, Felt y) public {
        vm.assume(y.isValid());

        Felt x = Fp.unsafeFromUint(_bound(xSeed, Secp256k1.P, type(uint).max));

        vm.expectRevert("PointInvalid()");
        wrapper.fromFelts(x, y);
    }

    function testFuzz_fromFelts_RevertsIf_PointInvalid_YCoordinateInvalidFelt(Felt x, uint ySeed) public {
        vm.assume(x.isValid());

        Felt y = Fp.unsafeFromUint(_bound(ySeed, Secp256k1.P, type(uint).max));

        vm.expectRevert("PointInvalid()");
        wrapper.fromFelts(x, y);
    }

    function testFuzz_fromFelts_FailsIf_PointInvalid_NotOnCurve(Felt x, Felt y) public {
        Point memory p = Point(x, y);
        vm.assume(!p.isOnCurve());

        vm.expectRevert("PointInvalid()");
        wrapper.fromFelts(x, y);
    }

    // -- unsafeFromFelts

    function testFuzz_unsafeFromFelts(Felt x, Felt y) public view {
        Point memory p = wrapper.unsafeFromFelts(x, y);
        assertEq(p.x.asUint(), x.asUint());
        assertEq(p.y.asUint(), y.asUint());
    }

    // -- TODO: tryFromUints

    // -- TODO: fromUints

    // -- TODO: unsafeFromUints

    // -- Identity

    function test_Identity() public view {
        assertTrue(wrapper.Identity().isIdentity());
    }

    // -- isIdentity

    function testFuzz_Point_isIdentity(Point memory point) public view {
        if (point.x.isZero() && point.y.isZero()) {
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

    function test_Point_isOnCurve_Identity() public view {
        assertTrue(wrapper.isOnCurve(Points.Identity()));
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
        bool ok;
        (point.x, ok) = Fp.tryFromUint(point.x.asUint() ^ xMask);
        vm.assume(ok);
        (point.y, ok) = Fp.tryFromUint(point.y.asUint() ^ yMask);
        vm.assume(ok);

        assertFalse(wrapper.isOnCurve(point));
    }

    // -- yParity

    function testFuzz_Point_yParity(Felt x, Felt y) public view {
        vm.assume(x.isValid());
        vm.assume(y.isValid());

        // yParity is 0 if y is even and 1 if y is odd.
        uint want = y.asUint() % 2 == 0 ? 0 : 1;
        uint got = wrapper.yParity(Points.unsafeFromFelts(x, y));

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

    // -- mulToAddress

    function testFuzz_Point_mulToAddress(SecretKey sk, uint scalarSeed)
        public
    {
        vm.assume(sk.isValid());

        Point memory point = sk.toPublicKey().intoPoint();
        uint scalar = _bound(scalarSeed, 1, Points.Q - 1);

        address got = wrapper.mulToAddress(point, scalar);
        // forgefmt: disable-next-item
        address want = point.toProjectivePoint()
                            .mul(scalar)
                            .intoPoint()
                            .intoPublicKey()
                            .toAddress();

        assertEq(got, want);
    }

    function testFuzz_Point_mulToAddress_ReturnsIdentityIfScalarIsZero(
        Point memory point
    ) public view {
        assertEq(
            wrapper.mulToAddress(point, 0),
            Points.Identity().intoPublicKey().toAddress()
        );
    }

    function testFuzz_Point_mulToAddress_RevertsIf_ScalarTooBig(
        Point memory point,
        uint scalar
    ) public {
        vm.assume(scalar >= Points.Q);

        vm.expectRevert("ScalarTooBig()");
        wrapper.mulToAddress(point, scalar);
    }

    //--------------------------------------------------------------------------
    // Test: Projective Point

    // -- ProjectiveIdentity

    function test_ProjectiveIdentity() public view {
        assertTrue(wrapper.ProjectiveIdentity().isIdentity());
    }

    // -- isIdentity

    function testFuzz_ProjectivePoint_isIdentity(ProjectivePoint memory point)
        public
        view
    {
        if (point.x.isZero() && point.z.isZero()) {
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
        uint sumScalar = addmod(sk1.asUint(), sk2.asUint(), Secp256k1.Q);
        vm.assume(sumScalar != 0);
        SecretKey sum = Secp256k1.secretKeyFromUint(sumScalar);

        // Compute want = [sum]G.
        Point memory want = sum.toPublicKey().intoPoint();

        // Compute got = [sk1]G + [sk2]G.
        ProjectivePoint memory left =
            Secp256k1.G().toProjectivePoint().mul(sk1.asUint());
        ProjectivePoint memory right =
            Secp256k1.G().toProjectivePoint().mul(sk2.asUint());
        Point memory got = left.add(right).intoPoint();

        assertTrue(want.eq(got));
    }

    function testVectors_ProjectivePoint_add() public view {
        ProjectivePoint memory g = Secp256k1.G().toProjectivePoint();
        ProjectivePoint memory p = Points.ProjectiveIdentity();

        Point[] memory vectors = PointsTestVectors.addVectors();

        for (uint i; i < vectors.length; i++) {
            p = wrapper.add(p, g);

            console.logBytes(vectors[i].toEncoded());

            assertTrue(p.toPoint().eq(vectors[i]));
        }
    }

    function test_ProjectivePoint_add_Identity() public view {
        ProjectivePoint memory g = Points.G().toProjectivePoint();
        ProjectivePoint memory id = Points.ProjectiveIdentity();
        Point memory got;

        // Test id + g.
        got = wrapper.add(id, g).intoPoint();
        assertTrue(got.eq(Points.G()));
        // Test g + id.
        got = wrapper.add(g, id).intoPoint();
        assertTrue(got.eq(Points.G()));
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

    function testFuzz_ProjectivePoint_mul(SecretKey sk) public {
        vm.assume(sk.isValid());

        ProjectivePoint memory g = Points.G().toProjectivePoint();

        Point memory got = wrapper.mul(g, sk.asUint()).intoPoint();
        Point memory want = sk.toPublicKey().intoPoint();

        assertTrue(want.eq(got));
    }

    function testVectors_ProjectivePoint_mul() public view {
        ProjectivePoint memory g = Secp256k1.G().toProjectivePoint();

        uint[] memory scalars;
        Point[] memory products;
        (scalars, products) = PointsTestVectors.mulVectors();

        for (uint i; i < scalars.length; i++) {
            Point memory p = wrapper.mul(g, scalars[i]).intoPoint();

            assertTrue(p.eq(products[i]));
        }
    }

    function testFuzz_ProjectivePoint_mul_ReturnsIdentityIfScalarIsZero(
        ProjectivePoint memory point
    ) public view {
        assertTrue(wrapper.mul(point, 0).isIdentity());
    }

    function testFuzz_ProjectivePoint_mul_ReturnsIdentityIfPointIsIdentity(
        SecretKey sk
    ) public view {
        vm.assume(sk.isValid());

        ProjectivePoint memory id = Points.ProjectiveIdentity();
        assertTrue(wrapper.mul(id, sk.asUint()).isIdentity());
    }

    function testFuzz_ProjectivePoint_mul_RevertsIf_ScalarTooBig(
        ProjectivePoint memory point,
        uint scalar
    ) public {
        vm.assume(scalar >= Points.Q);

        vm.expectRevert("ScalarTooBig()");
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

    function test_Point_toProjectivePoint_Identity() public view {
        Point memory identity = Points.Identity();

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
        uint scalar = addmod(a.asUint(), b.asUint(), Secp256k1.Q);
        Point memory want =
            Secp256k1.secretKeyFromUint(scalar).toPublicKey().intoPoint();

        // Compute [a]G + [b]G via ProjectivePoints.
        // forgefmt: disable-next-item
        ProjectivePoint memory sum = a.toPublicKey().toProjectivePoint()
                                      .add(b.toPublicKey().toProjectivePoint());

        Point memory got = wrapper.intoPoint(sum);

        assertTrue(want.eq(got));
    }

    function test_ProjectivePoint_intoPoint_Identity() public view {
        ProjectivePoint memory identity = Points.ProjectiveIdentity();

        assertTrue(wrapper.intoPoint(identity).isIdentity());
    }

    // -- toPoint

    function test_ProjectivePoint_toPoint(SecretKey a, SecretKey b) public {
        vm.assume(a.isValid());
        vm.assume(b.isValid());

        // To produce random ProjectivePoints with non-zero z coordinate, add
        // two random points via ProjectivePoint::add().

        // Compute [a+b]G.
        uint scalar = addmod(a.asUint(), b.asUint(), Secp256k1.Q);
        Point memory want =
            Secp256k1.secretKeyFromUint(scalar).toPublicKey().intoPoint();

        // Compute [a]G + [b]G via ProjectivePoints.
        // forgefmt: disable-next-item
        ProjectivePoint memory sum = a.toPublicKey().toProjectivePoint()
                                      .add(b.toPublicKey().toProjectivePoint());

        Point memory got = wrapper.toPoint(sum);

        assertTrue(want.eq(got));
    }

    function test_ProjectivePoint_toPoint_Identity() public view {
        ProjectivePoint memory identity = Points.ProjectiveIdentity();

        assertTrue(wrapper.toPoint(identity).isIdentity());
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    // -- Point <-> Encoded

    function test_pointFromEncoded() public view {
        bytes memory blob;
        Point memory point;

        // Generator.
        blob = GENERATOR_ENCODED;
        point = wrapper.pointFromEncoded(blob);
        assertTrue(point.eq(Points.G()));

        // Some other point, ie [2]G.
        blob =
            hex"04C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE51AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A";
        point = wrapper.pointFromEncoded(blob);
        // forgefmt: disable-next-item
        assertTrue(
            point.eq(
                Point(
                    Fp.unsafeFromUint(uint(0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5)),
                    Fp.unsafeFromUint(uint(0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A))
                )
            )
        );
    }

    function test_pointFromEncoded_Identity() public view {
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

        vm.expectRevert("PointInvalid()");
        wrapper.pointFromEncoded(blob);
    }

    function test_Point_toEncoded() public view {
        Point memory point;
        bytes memory blob;

        // Generator.
        point = Points.G();
        blob = wrapper.toEncoded(point);
        assertEq(blob, GENERATOR_ENCODED);

        // Some other point, ie [2]G.
        // forgefmt: disable-next-item
        point = Point(
            Fp.unsafeFromUint(uint(0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5)),
            Fp.unsafeFromUint(uint(0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A))
        );
        blob = wrapper.toEncoded(point);
        assertEq(
            blob,
            hex"04C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE51AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"
        );
    }

    function test_Point_toEncoded_Identity() public view {
        Point memory point = Points.Identity();
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

    function test_Point_pointFromCompressedEncoded() public view {
        bytes memory blob;
        Point memory point;

        // Generator.
        blob = GENERATOR_COMPRESSED_ENCODED;
        point = wrapper.pointFromCompressedEncoded(blob);
        assertTrue(point.eq(Points.G()));
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

    function test_Point_pointFromCompressedEncoded_Identity() public view {
        Point memory id = Points.Identity();

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
    )
        /*Point memory point*/
        public
    {
        vm.skip(true);
        // TODO: Find secp256k1 x coordinates not on the curve for compressed
        //       byte encoding.
    }

    function test_Point_toCompressedEncoded_IfyParityEven() public view {
        // Some point, ie [2]G.
        // forgefmt: disable-next-item
        Point memory point = Point(
            Fp.unsafeFromUint(uint(0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5)),
            Fp.unsafeFromUint(uint(0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A))
        );
        bytes memory blob = wrapper.toCompressedEncoded(point);

        assertEq(
            blob,
            hex"02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"
        );
    }

    function test_Point_toCompressedEncoded_IfyParityOdd() public view {
        // Some point, ie [6]G.
        // forgefmt: disable-next-item
        Point memory point = Point(
            Fp.unsafeFromUint(uint(0xFFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556)),
            Fp.unsafeFromUint(uint(0xAE12777AACFBB620F3BE96017F45C560DE80F0F6518FE4A03C870C36B075F297))
        );
        bytes memory blob = wrapper.toCompressedEncoded(point);

        assertEq(
            blob,
            hex"03FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556"
        );
    }

    function test_Point_toCompressedEncoded_Identity() public view {
        Point memory point = Points.Identity();
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
contract PointsWrapper {
    using Points for Point;
    using Points for ProjectivePoint;

    //--------------------------------------------------------------------------
    // Test: Constants

    function G() public pure returns (Point memory) {
        return Points.G();
    }

    //--------------------------------------------------------------------------
    // Point

    function tryFromFelts(Felt x, Felt y)
        public
        pure
        returns (Point memory, bool)
    {
        return Points.tryFromFelts(x, y);
    }

    function fromFelts(Felt x, Felt y)
        public
        pure
        returns (Point memory)
    {
        return Points.fromFelts(x, y);
    }

    function unsafeFromFelts(Felt x, Felt y)
        public
        pure
        returns (Point memory)
    {
        return Points.unsafeFromFelts(x, y);
    }

    function tryFromUints(uint x, uint y)
        public
        pure
        returns (Point memory, bool)
    {
        return Points.tryFromUints(x, y);
    }

    function fromUints(uint x, uint y) internal pure returns (Point memory) {
        return Points.fromUints(x, y);
    }

    function unsafeFromUints(uint x, uint y)
        public
        pure
        returns (Point memory)
    {
        return Points.unsafeFromUints(x, y);
    }

    function Identity() public pure returns (Point memory) {
        return Points.Identity();
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
        return Points.ProjectiveIdentity();
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
        return Points.pointFromEncoded(blob);
    }

    function toEncoded(Point memory point) public pure returns (bytes memory) {
        return point.toEncoded();
    }

    function pointFromCompressedEncoded(bytes memory blob)
        public
        view
        returns (Point memory)
    {
        return Points.pointFromCompressedEncoded(blob);
    }

    function toCompressedEncoded(Point memory point)
        public
        pure
        returns (bytes memory)
    {
        return point.toCompressedEncoded();
    }
}
