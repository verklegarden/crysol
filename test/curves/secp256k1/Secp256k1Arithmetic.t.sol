// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256k1, SecretKey, PublicKey} from "src/curves/Secp256k1.sol";
import {
    Secp256k1Arithmetic,
    Point,
    ProjectivePoint
} from "src/curves/Secp256k1Arithmetic.sol";

/**
 * @notice Secp256k1Arithmetic Unit Tests
 */
contract Secp256k1ArithmeticTest is Test {
    using Secp256k1Arithmetic for Point;
    using Secp256k1Arithmetic for ProjectivePoint;

    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    Secp256k1ArithmeticWrapper wrapper;

    function setUp() public {
        wrapper = new Secp256k1ArithmeticWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Point

    // -- ZeroPoint

    function test_ZeroPoint() public {
        assertTrue(wrapper.ZeroPoint().isZeroPoint());
    }

    // -- isZeroPoint

    function testFuzz_Point_isZeroPoint(Point memory point) public {
        if (point.x == 0 && point.y == 0) {
            assertTrue(wrapper.isZeroPoint(point));
        } else {
            assertFalse(wrapper.isZeroPoint(point));
        }
    }

    // -- Identity

    function test_Identity() public {
        assertTrue(wrapper.Identity().isIdentity());
    }

    // -- isIdentity

    function testFuzz_Point_isIdentity(Point memory point) public {
        if (point.x == type(uint).max && point.y == type(uint).max) {
            assertTrue(wrapper.isIdentity(point));
        } else {
            assertFalse(wrapper.isIdentity(point));
        }
    }

    // -- isOnCurve

    function testVectors_Point_isOnCurve() public {
        assertTrue(wrapper.isOnCurve(wrapper.G()));

        // TODO: Test Point.isOnCurve(): Add more points.
    }

    function testFuzz_Point_isOnCurve(SecretKey sk) public {
        vm.assume(sk.isValid());

        Point memory point = sk.toPublicKey().intoPoint();

        assertTrue(wrapper.isOnCurve(point));
    }

    function test_Point_isOnCurve_Identity() public {
        assertTrue(wrapper.isOnCurve(Secp256k1Arithmetic.Identity()));
    }

    // -- yParity

    function testFuzz_Point_yParity(uint x, uint y) public {
        // yParity is 0 if y is even and 1 if y is odd.
        uint want = y % 2 == 0 ? 0 : 1;
        uint got = wrapper.yParity(Point(x, y));

        assertEq(want, got);
    }

    // -- equals

    function testFuzz_Point_equals(SecretKey sk) public {
        vm.assume(sk.isValid());

        Point memory point = sk.toPublicKey().intoPoint();

        assertTrue(wrapper.equals(point, point));
    }

    function testFuzz_Point_equals_FailsIfPointsDoNotEqual(
        SecretKey sk1,
        SecretKey sk2
    ) public {
        vm.assume(sk1.asUint() != sk2.asUint());
        vm.assume(sk1.isValid());
        vm.assume(sk2.isValid());

        Point memory point1 = sk1.toPublicKey().intoPoint();
        Point memory point2 = sk2.toPublicKey().intoPoint();

        assertFalse(wrapper.equals(point1, point2));
    }

    function test_Point_equals_DoesNotRevert_IfPointsNotOnCurve(
        Point memory point1,
        Point memory point2
    ) public view {
        wrapper.equals(point1, point2);
    }

    //----------------------------------
    // Test: Type Conversion

    // -- toProjectivePoint

    function testFuzz_Point_toProjectivePoint(SecretKey sk) public {
        vm.assume(sk.isValid());

        Point memory want = sk.toPublicKey().intoPoint();
        Point memory got = wrapper.toProjectivePoint(want).intoPoint();

        assertEq(want.x, got.x);
        assertEq(want.y, got.y);
    }

    //--------------------------------------------------------------------------
    // Test: Projective Point

    // -- isIdentity

    function testFuzz_ProjectivePoint_isIdentity(ProjectivePoint memory point)
        public
    {
        if (point.x == 0 && point.y == 1 && point.z == 0) {
            assertTrue(wrapper.isIdentity(point));
        } else {
            assertFalse(wrapper.isIdentity(point));
        }
    }

    //----------------------------------
    // Test: Arithmetic

    /*
    function test_ProjectivePoint_add() public {
    (
        hex!("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        hex!("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
    ),
    (
        hex!("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"),
        hex!("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"),
    ),
    (
        hex!("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
        hex!("388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672"),
    ),
    (
        hex!("E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13"),
        hex!("51ED993EA0D455B75642E2098EA51448D967AE33BFBDFE40CFE97BDC47739922"),
    ),
    (
        hex!("2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4"),
        hex!("D8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6"),
    ),
    (
        hex!("FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556"),
        hex!("AE12777AACFBB620F3BE96017F45C560DE80F0F6518FE4A03C870C36B075F297"),
    ),
    (
        hex!("5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC"),
        hex!("6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA"),
    ),
    (
        hex!("2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01"),
        hex!("5C4DA8A741539949293D082A132D13B4C2E213D6BA5B7617B5DA2CB76CBDE904"),
    ),
    (
        hex!("ACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBE"),
        hex!("CC338921B0A7D9FD64380971763B61E9ADD888A4375F8E0F05CC262AC64F9C37"),
    ),
    (
        hex!("A0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7"),
        hex!("893ABA425419BC27A3B6C7E693A24C696F794C2ED877A1593CBEE53B037368D7"),
    ),
    (
        hex!("774AE7F858A9411E5EF4246B70C65AAC5649980BE5C17891BBEC17895DA008CB"),
        hex!("D984A032EB6B5E190243DD56D7B7B365372DB1E2DFF9D6A8301D74C9C953C61B"),
    ),
    (
        hex!("D01115D548E7561B15C38F004D734633687CF4419620095BC5B0F47070AFE85A"),
        hex!("A9F34FFDC815E0D7A8B64537E17BD81579238C5DD9A86D526B051B13F4062327"),
    ),
    (
        hex!("F28773C2D975288BC7D1D205C3748651B075FBC6610E58CDDEEDDF8F19405AA8"),
        hex!("0AB0902E8D880A89758212EB65CDAF473A1A06DA521FA91F29B5CB52DB03ED81"),
    ),
    (
        hex!("499FDF9E895E719CFD64E67F07D38E3226AA7B63678949E6E49B241A60E823E4"),
        hex!("CAC2F6C4B54E855190F044E4A7B3D464464279C27A3F95BCC65F40D403A13F5B"),
    ),
    (
        hex!("D7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080E"),
        hex!("581E2872A86C72A683842EC228CC6DEFEA40AF2BD896D3A5C504DC9FF6A26B58"),
    ),
    (
        hex!("E60FCE93B59E9EC53011AABC21C23E97B2A31369B87A5AE9C44EE89E2A6DEC0A"),
        hex!("F7E3507399E595929DB99F34F57937101296891E44D23F0BE1F32CCE69616821"),
    ),
    (
        hex!("DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"),
        hex!("4211AB0694635168E997B0EAD2A93DAECED1F4A04A95C0F6CFB199F69E56EB77"),
    ),
    (
        hex!("5601570CB47F238D2B0286DB4A990FA0F3BA28D1A319F5E7CF55C2A2444DA7CC"),
        hex!("C136C1DC0CBEB930E9E298043589351D81D8E0BC736AE2A1F5192E5E8B061D58"),
    ),
    (
        hex!("2B4EA0A797A443D293EF5CFF444F4979F06ACFEBD7E86D277475656138385B6C"),
        hex!("85E89BC037945D93B343083B5A1C86131A01F60C50269763B570C854E5C09B7A"),
    ),
    (
        hex!("4CE119C96E2FA357200B559B2F7DD5A5F02D5290AFF74B03F3E471B273211C97"),
        hex!("12BA26DCB10EC1625DA61FA10A844C676162948271D96967450288EE9233DC3A"),
    ),
    }
    */

    function test_ProjectivePoint_add() public {
        ProjectivePoint memory g = Secp256k1Arithmetic.G().toProjectivePoint();

        // want = [2]G
        SecretKey sk = Secp256k1.secretKeyFromUint(2);
        Point memory want = sk.toPublicKey().intoPoint();

        // got: G + G
        ProjectivePoint memory jPoint = wrapper.add(g, g);
        console.log("jPoint.x", jPoint.x);
        console.log("jPoint.y", jPoint.y);
        console.log("jPoint.z", jPoint.z);

        Point memory got = wrapper.add(g, g).intoPoint();

        // Want:
        // x: 89565891926547004231252920425935692360644145829622209833684329913297188986597
        // y: 12158399299693830322967808612713398636155367887041628176798871954788371653930

        // Alg 1:
        // x: 10962303011661563909760120580420572844268442539981607763544518030530584249896
        // y: 73466120800335599957096923879044237072732953459294722407059852471027259622578
        //
        // jPoint.x 13181156486935683610805726302064329274717629062639299519950901153253244018254
        // jPoint.y 39155707150128334349216371677407456506802956851096117747929288260567018884059  <
        // jPoint.z 93461060555196532511955904293955655567833845947013025069247287831448311466323

        // Alg 7:
        // x: 87391808355972582617912962196687600089218617032645942978517463571946182934760
        // y: 59798459239490663731683313163756213699029087070685955441295759628293051219517
        //
        // jPoint.x 110383685576993659245168857245613307344564578195757623090394588386385391034312
        // jPoint.y 39155707150128334349216371677407456506802956851096117747929288260567018884059  <
        // jPoint.z 112386024462437979217642839804619380985487717678471186887195924032703633398313
        
        assertEq(want.x, got.x);
        assertEq(want.y, got.y);
    }

    /*
    function testFuzz_ProjectivePoint_add_Generator(SecretKey sk) {
        public
    {
        //vm.assume(sk.isValid());
        //vm.assume(sk.asUint() < 100);

        SecretKey sk = Secp256k1.secretKeyFromUint(2);

        Point memory want = sk.toPublicKey().intoPoint();

        ProjectivePoint memory g = Secp256k1Arithmetic.G().toProjectivePoint();
        ProjectivePoint memory id =
            Secp256k1Arithmetic.Identity().toProjectivePoint();

        ProjectivePoint memory sum = id;
        for (uint i; i < sk.asUint(); i++) {
            sum = sum.add(g);
        }

        Point memory got = sum.intoPoint();

        assertEq(want.x, got.x);
        assertEq(want.y, got.y);
    }
    */

    function test_ProjectivePoint_add_Identity() public {
        ProjectivePoint memory g = Secp256k1Arithmetic.G().toProjectivePoint();
        ProjectivePoint memory id =
            Secp256k1Arithmetic.Identity().toProjectivePoint();

        Point memory sum;

        sum = wrapper.add(g, id).intoPoint();
        assertEq(sum.x, g.x);
        assertEq(sum.y, g.y);

        sum = wrapper.add(id, g).intoPoint();
        assertEq(sum.x, g.x);
        assertEq(sum.y, g.y);
    }

    //----------------------------------
    // Test: Type Conversion

    // TODO: Test no new memory allocation.
    // TODO: Not a real test. Use vectors from Paul Miller.
    function testFuzz_ProjectivePoint_intoPoint(SecretKey sk) public {
        vm.assume(sk.isValid());

        Point memory want = sk.toPublicKey().intoPoint();
        Point memory got = wrapper.intoPoint(want.toProjectivePoint());

        assertEq(want.x, got.x);
        assertEq(want.y, got.y);
    }

    function test_ProjectivePoint_intoPoint_IsIdentityIfIdentity() public {
        // TODO: Make Identity()(ProjectivePoint) function!
        ProjectivePoint memory id = ProjectivePoint(0, 1, 0);

        assertTrue(wrapper.intoPoint(id).isIdentity());
    }

    //--------------------------------------------------------------------------
    // Test: Utils

    // -- modularInverseOf

    function testFuzz_modularInverseOf(uint x) public {
        vm.assume(x != 0);
        vm.assume(x < Secp256k1Arithmetic.P);

        uint xInv = Secp256k1Arithmetic.modularInverseOf(x);

        // Verify x * xInv ≡ 1 (mod P).
        assertEq(mulmod(x, xInv, Secp256k1Arithmetic.P), 1);
    }

    function test_modularInverseOf_RevertsIf_XIsZero() public {
        // TODO: Test for proper error message.
        vm.expectRevert();
        wrapper.modularInverseOf(0);
    }

    function testFuzz_modularInverseOf_RevertsIf_XEqualToOrBiggerThanP(uint x)
        public
    {
        vm.assume(x >= Secp256k1Arithmetic.P);

        vm.expectRevert("NotAFieldElement(x)");
        wrapper.modularInverseOf(x);
    }

    // -- areModularInverse

    function testFuzz_areModularInverse(uint x) public {
        vm.assume(x != 0);
        vm.assume(x < Secp256k1Arithmetic.P);

        assertTrue(
            wrapper.areModularInverse(
                x, Secp256k1Arithmetic.modularInverseOf(x)
            )
        );
    }

    function testFuzz_areModularInverse_FailsIf_NotModularInverse(
        uint x,
        uint xInv
    ) public {
        vm.assume(x < Secp256k1Arithmetic.P);
        vm.assume(xInv < Secp256k1Arithmetic.P);

        vm.assume(mulmod(x, xInv, Secp256k1Arithmetic.P) != 1);

        assertFalse(wrapper.areModularInverse(x, xInv));
    }

    function testFuzz_areModularInverse_RevertsIf_XEqualToOrBiggerThanP(uint x)
        public
    {
        vm.assume(x >= Secp256k1Arithmetic.P);

        vm.expectRevert("NotAFieldElement(x)");
        wrapper.areModularInverse(x, 1);
    }

    function testFuzz_areModularInverse_RevertsIf_XInvEqualToOrBiggerThanP(
        uint xInv
    ) public {
        vm.assume(xInv >= Secp256k1Arithmetic.P);

        vm.expectRevert("NotAFieldElement(xInv)");
        wrapper.areModularInverse(1, xInv);
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

    function ZeroPoint() public pure returns (Point memory) {
        return Secp256k1Arithmetic.ZeroPoint();
    }

    function isZeroPoint(Point memory point) public pure returns (bool) {
        return point.isZeroPoint();
    }

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

    function equals(Point memory point, Point memory other)
        public
        pure
        returns (bool)
    {
        return point.equals(other);
    }

    //--------------------------------------------------------------------------
    // Projective Point

    function isIdentity(ProjectivePoint memory point)
        public
        pure
        returns (bool)
    {
        return point.isIdentity();
    }

    //----------------------------------
    // Arithmetic

    function add(ProjectivePoint memory point, ProjectivePoint memory other)
        public
        pure
        returns (ProjectivePoint memory)
    {
        return point.add(other);
    }

    function mul(ProjectivePoint memory point, uint scalar)
        public
        pure
        returns (ProjectivePoint memory)
    {
        return point.mul(scalar);
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

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

    function intoPoint(ProjectivePoint memory jPoint)
        public
        pure
        returns (Point memory)
    {
        return jPoint.intoPoint();
    }

    //--------------------------------------------------------------------------
    // Utils

    function modularInverseOf(uint x) public pure returns (uint) {
        return Secp256k1Arithmetic.modularInverseOf(x);
    }

    function areModularInverse(uint x, uint xInv) public pure returns (bool) {
        return Secp256k1Arithmetic.areModularInverse(x, xInv);
    }
}
