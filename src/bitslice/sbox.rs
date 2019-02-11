use core::ops;

use crate::aes::ops::SubBytes;
use super::Bitslice;

impl<W> SubBytes for Bitslice<W>
    where W: Copy
           + ops::BitXor<Output = W>
           + ops::BitAnd<Output = W>
           + ops::Not<Output = W>
{
    /// Computes AES `SubBytes` in-place for all bytes in this `Bitslice`.
    ///
    /// This is derived from a [hardware implementation][impl] of the Rijndael S-box by
    /// Yale's [Circuit Minimization Team][cmt].
    ///
    /// To be suitable for use in the bitslice paradigm, a hardware implementation should:
    ///
    /// 1. Use as few operations as possible. The number of operations is not necessarily the same
    ///    as the gate count, since most ISAs require two instructions for NAND, NOR and XNOR.
    ///
    /// 2. Be shallow enough to allow for ILP, but deep enough that registers aren't exhausted.
    ///
    /// [impl]: https://web.archive.org/web/20181025225316/http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt
    /// [cmt]: http://www.cs.yale.edu/homes/peralta/CircuitStuff/CMT.html
    fn sub_bytes(&mut self) {
        // 8 inputs
        // msb      ->         lsb
        // U0 U1 U2 U3 U4 U5 U6 U7
        let Bitslice([u7, u6, u5, u4, u3, u2, u1, u0]) = *self;

        // 113 gates
        // 32 ANDs, 77 XORs, 4 XNORs
        // Depth 28
        let y14 = u3 ^ u5;
        let y13 = u0 ^ u6;
        let y9 = u0 ^ u3;
        let y8 = u0 ^ u5;
        let t0 = u1 ^ u2;
        let y1 = t0 ^ u7;
        let y4 = y1 ^ u3;
        let y12 = y13 ^ y14;
        let y2 = y1 ^ u0;
        let y5 = y1 ^ u6;
        let y3 = y5 ^ y8;
        let t1 = u4 ^ y12;
        let y15 = t1 ^ u5;
        let y20 = t1 ^ u1;
        let y6 = y15 ^ u7;
        let y10 = y15 ^ t0;
        let y11 = y20 ^ y9;
        let y7 = u7 ^ y11;
        let y17 = y10 ^ y11;
        let y19 = y10 ^ y8;
        let y16 = t0 ^ y11;
        let y21 = y13 ^ y16;
        let y18 = u0 ^ y16;
        let t2 = y12 & y15;
        let t3 = y3 & y6;
        let t4 = t3 ^ t2;
        let t5 = y4 & u7;
        let t6 = t5 ^ t2;
        let t7 = y13 & y16;
        let t8 = y5 & y1;
        let t9 = t8 ^ t7;
        let t10 = y2 & y7;
        let t11 = t10 ^ t7;
        let t12 = y9 & y11;
        let t13 = y14 & y17;
        let t14 = t13 ^ t12;
        let t15 = y8 & y10;
        let t16 = t15 ^ t12;
        let t17 = t4 ^ y20;
        let t18 = t6 ^ t16;
        let t19 = t9 ^ t14;
        let t20 = t11 ^ t16;
        let t21 = t17 ^ t14;
        let t22 = t18 ^ y19;
        let t23 = t19 ^ y21;
        let t24 = t20 ^ y18;
        let t25 = t21 ^ t22;
        let t26 = t21 & t23;
        let t27 = t24 ^ t26;
        let t28 = t25 & t27;
        let t29 = t28 ^ t22;
        let t30 = t23 ^ t24;
        let t31 = t22 ^ t26;
        let t32 = t31 & t30;
        let t33 = t32 ^ t24;
        let t34 = t23 ^ t33;
        let t35 = t27 ^ t33;
        let t36 = t24 & t35;
        let t37 = t36 ^ t34;
        let t38 = t27 ^ t36;
        let t39 = t29 & t38;
        let t40 = t25 ^ t39;
        let t41 = t40 ^ t37;
        let t42 = t29 ^ t33;
        let t43 = t29 ^ t40;
        let t44 = t33 ^ t37;
        let t45 = t42 ^ t41;
        let z0 = t44 & y15;
        let z1 = t37 & y6;
        let z2 = t33 & u7;
        let z3 = t43 & y16;
        let z4 = t40 & y1;
        let z5 = t29 & y7;
        let z6 = t42 & y11;
        let z7 = t45 & y17;
        let z8 = t41 & y10;
        let z9 = t44 & y12;
        let z10 = t37 & y3;
        let z11 = t33 & y4;
        let z12 = t43 & y13;
        let z13 = t40 & y5;
        let z14 = t29 & y2;
        let z15 = t42 & y9;
        let z16 = t45 & y14;
        let z17 = t41 & y8;
        let tc1 = z15 ^ z16;
        let tc2 = z10 ^ tc1;
        let tc3 = z9 ^ tc2;
        let tc4 = z0 ^ z2;
        let tc5 = z1 ^ z0;
        let tc6 = z3 ^ z4;
        let tc7 = z12 ^ tc4;
        let tc8 = z7 ^ tc6;
        let tc9 = z8 ^ tc7;
        let tc10 = tc8 ^ tc9;
        let tc11 = tc6 ^ tc5;
        let tc12 = z3 ^ z5;
        let tc13 = z13 ^ tc1;
        let tc14 = tc4 ^ tc12;
        let s3 = tc3 ^ tc11;
        let tc16 = z6 ^ tc8;
        let tc17 = z14 ^ tc10;
        let tc18 = tc13 ^ tc14;
        let s7 = !(z12 ^ tc18);
        let tc20 = z15 ^ tc16;
        let tc21 = tc2 ^ z11;
        let s0 = tc3 ^ tc16;
        let s6 = !(tc10 ^ tc18);
        let s4 = tc14 ^ s3;
        let s1 = !(s3 ^ tc16);
        let tc26 = tc17 ^ tc20;
        let s2 = !(tc26 ^ z17);
        let s5 = tc21 ^ tc17;

        // 8 outputs
        // S3 S7 S0 S6 S4 S1 S2 S5
        *self = Bitslice([s7, s6, s5, s4, s3, s2, s1, s0]);
    }

    #[allow(non_snake_case)]
    fn inv_sub_bytes(&mut self) {
        // 8 inputs
        // msb      ->         lsb
        // U0 U1 U2 U3 U4 U5 U6 U7
        let Bitslice([u7, u6, u5, u4, u3, u2, u1, u0]) = *self;

        // 121 gates
        let Y0 = u0 ^ u3;
        let Y2 = !(u1 ^ u3);
        let Y4 = u0 ^ Y2;
        let RTL0 = u6 ^ u7;
        let Y1 = Y2 ^ RTL0;
        let Y7 = !(u2 ^ Y1);
        let RTL1 = u3 ^ u4;
        let Y6 = !(u7 ^ RTL1);
        let Y3 = Y1 ^ RTL1;
        let RTL2 = !(u0 ^ u2);
        let Y5 = u5 ^ RTL2;
        let sa1 = Y0 ^ Y2;
        let sa0 = Y1 ^ Y3;
        let sb1 = Y4 ^ Y6;
        let sb0 = Y5 ^ Y7;
        let ah = Y0 ^ Y1;
        let al = Y2 ^ Y3;
        let aa = sa0 ^ sa1;
        let bh = Y4 ^ Y5;
        let bl = Y6 ^ Y7;
        let bb = sb0 ^ sb1;
        let ab20 = sa0 ^ sb0;
        let ab22 = al ^ bl;
        let ab23 = Y3 ^ Y7;
        let ab21 = sa1 ^ sb1;
        let abcd1 = ah & bh;
        let rr1 = Y0 & Y4;
        let ph11 = ab20 ^ abcd1;
        let t01 = Y1 & Y5;
        let ph01 = t01 ^ abcd1;
        let abcd2 = al & bl;
        let r1 = Y2 & Y6;
        let pl11 = ab22 ^ abcd2;
        let r2 = Y3 & Y7;
        let pl01 = r2 ^ abcd2;
        let r3 = sa0 & sb0;
        let vr1 = aa & bb;
        let pr1 = vr1 ^ r3;
        let wr1 = sa1 & sb1;
        let qr1 = wr1 ^ r3;
        let ab0 = ph11 ^ rr1;
        let ab1 = ph01 ^ ab21;
        let ab2 = pl11 ^ r1;
        let ab3 = pl01 ^ qr1;
        let cp1 = ab0 ^ pr1;
        let cp2 = ab1 ^ qr1;
        let cp3 = ab2 ^ pr1;
        let cp4 = ab3 ^ ab23;
        let tinv1 = cp3 ^ cp4;
        let tinv2 = cp3 & cp1;
        let tinv3 = cp2 ^ tinv2;
        let tinv4 = cp1 ^ cp2;
        let tinv5 = cp4 ^ tinv2;
        let tinv6 = tinv5 & tinv4;
        let tinv7 = tinv3 & tinv1;
        let d2 = cp4 ^ tinv7;
        let d0 = cp2 ^ tinv6;
        let tinv8 = cp1 & cp4;
        let tinv9 = tinv4 & tinv8;
        let tinv10 = tinv4 ^ tinv2;
        let d1 = tinv9 ^ tinv10;
        let tinv11 = cp2 & cp3;
        let tinv12 = tinv1 & tinv11;
        let tinv13 = tinv1 ^ tinv2;
        let d3 = tinv12 ^ tinv13;
        let sd1 = d1 ^ d3;
        let sd0 = d0 ^ d2;
        let dl = d0 ^ d1;
        let dh = d2 ^ d3;
        let dd = sd0 ^ sd1;
        let abcd3 = dh & bh;
        let rr2 = d3 & Y4;
        let t02 = d2 & Y5;
        let abcd4 = dl & bl;
        let r4 = d1 & Y6;
        let r5 = d0 & Y7;
        let r6 = sd0 & sb0;
        let vr2 = dd & bb;
        let wr2 = sd1 & sb1;
        let abcd5 = dh & ah;
        let r7 = d3 & Y0;
        let r8 = d2 & Y1;
        let abcd6 = dl & al;
        let r9 = d1 & Y2;
        let r10 = d0 & Y3;
        let r11 = sd0 & sa0;
        let vr3 = dd & aa;
        let wr3 = sd1 & sa1;
        let ph12 = rr2 ^ abcd3;
        let ph02 = t02 ^ abcd3;
        let pl12 = r4 ^ abcd4;
        let pl02 = r5 ^ abcd4;
        let pr2 = vr2 ^ r6;
        let qr2 = wr2 ^ r6;
        let p0 = ph12 ^ pr2;
        let p1 = ph02 ^ qr2;
        let p2 = pl12 ^ pr2;
        let p3 = pl02 ^ qr2;
        let ph13 = r7 ^ abcd5;
        let ph03 = r8 ^ abcd5;
        let pl13 = r9 ^ abcd6;
        let pl03 = r10 ^ abcd6;
        let pr3 = vr3 ^ r11;
        let qr3 = wr3 ^ r11;
        let p4 = ph13 ^ pr3;
        let S7 = ph03 ^ qr3;
        let p6 = pl13 ^ pr3;
        let p7 = pl03 ^ qr3;
        let S3 = p1 ^ p6;
        let S6 = p2 ^ p6;
        let S0 = p3 ^ p6;
        let X11 = p0 ^ p2;
        let S5 = S0 ^ X11;
        let X13 = p4 ^ p7;
        let X14 = X11 ^ X13;
        let S1 = S3 ^ X14;
        let X16 = p1 ^ S7;
        let S2 = X14 ^ X16;
        let X18 = p0 ^ p4;
        let X19 = S5 ^ X16;
        let S4 = X18 ^ X19;

        // 8 outputs
        // S0 S1 S2 S3 S4 S5 S6 S7
        *self = Bitslice([S7, S6, S5, S4, S3, S2, S1, S0]);
    }
}

