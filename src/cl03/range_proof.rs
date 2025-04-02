// Copyright 2025 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::commitment::CL03Commitment;
use crate::utils::{random::rand_int, util::cl03_utils::divm};
use digest::Digest;
use rug::{integer::Order, ops::Pow, Complete, Integer};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum RangeProof {
    Boudot2000,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct ProofSs {
    challenge: Integer,
    d: Integer,
    d_1: Integer,
    d_2: Integer,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct ProofOfS {
    E: Integer,
    F: Integer,
    proof_ss: ProofSs,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct ProofLi {
    C: Integer,
    D_1: Integer,
    D_2: Integer,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ProofWt {
    E_a_1: Integer,
    E_a_2: Integer,
    E_b_1: Integer,
    E_b_2: Integer,
    proof_of_square_a: ProofOfS,
    proof_of_square_b: ProofOfS,
    proof_large_i_a: ProofLi,
    proof_large_i_b: ProofLi,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Boudot2000RangeProof {
    pub proof_of_tolerance: ProofWt,
    pub E_prime: Integer,
    pub E: Integer,
}

impl Boudot2000RangeProof {
    /* Security parameter - Half of the length of the Hash function output
    NOTE: i.e., 2*t bits is the length of the Hash function output.
    The soundness characteristic of the range proof is given by 2**(t−1).
    t = 80: Original value in [Boudot2000], appropriate for SHA-1 - sha160 (i.e. 2*t = 160 bits),
    replaced by t = 128, appropriate for SHA256 (i.e. 2*t = 256). */
    const t: u32 = 128;
    // Security parameter - Zero knowledge property is guaranteed given that 1∕l is negligible
    const l: u32 = 40;
    // Security parameter for the commitment - 2**s  must be negligible
    const s: u32 = 40;
    // Security parameter for the commitment - 2**s1 must be negligible
    const s1: u32 = 40;
    // Security parameter for the commitment - 2**s2 must be negligible
    const s2: u32 = 552;

    /* Algorithm 1 Proof of Same Secret */
    fn proof_same_secret<H>(
        x: &Integer,
        r_1: &Integer,
        r_2: &Integer,
        g_1: &Integer,
        h_1: &Integer,
        g_2: &Integer,
        h_2: &Integer,
        l: u32,
        t: u32,
        b: &Integer,
        s1: u32,
        s2: u32,
        n: &Integer,
    ) -> ProofSs
    where
        H: Digest,
    {
        let omega = rand_int(
            Integer::from(1),
            Integer::from(2).pow(l + t) * b - Integer::from(1),
        );
        let mu_1 = rand_int(
            Integer::from(1),
            Integer::from(2).pow(l + t + s1) * n - Integer::from(1),
        );
        let mu_2 = rand_int(
            Integer::from(1),
            Integer::from(2).pow(l + t + s2) * n - Integer::from(1),
        );
        let w_1 = (Integer::from(g_1.pow_mod_ref(&omega, n).unwrap())
            * Integer::from(h_1.pow_mod_ref(&mu_1, n).unwrap()))
            % n;
        let w_2 = (Integer::from(g_2.pow_mod_ref(&omega, n).unwrap())
            * Integer::from(h_2.pow_mod_ref(&mu_2, n).unwrap()))
            % n;

        let str = w_1.to_string() + &w_2.to_string();
        let hash = <H as Digest>::digest(str);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        let d = omega + &challenge * x;
        let d_1 = mu_1 + &challenge * r_1;
        let d_2 = mu_2 + &challenge * r_2;

        ProofSs {
            challenge,
            d,
            d_1,
            d_2,
        }
        // proof_ss = {'challenge': int(challenge), 'd': int(d), 'd_1': int(d_1), 'd_2': int(d_2)}
    }

    /* Algorithm 2 Verify Proof of Same Secret*/
    fn verify_same_secret<H>(
        E: &Integer,
        F: &Integer,
        g_1: &Integer,
        h_1: &Integer,
        g_2: &Integer,
        h_2: &Integer,
        n: &Integer,
        proof_ss: &ProofSs,
    ) -> bool
    where
        H: Digest,
    {
        let ProofSs {
            challenge,
            d,
            d_1,
            d_2,
        } = proof_ss;

        let inv_E = Integer::from(E.pow_mod_ref(&(-Integer::from(1) * challenge), n).unwrap());
        let inv_F = Integer::from(F.pow_mod_ref(&(-Integer::from(1) * challenge), n).unwrap());

        let lhs = (Integer::from(g_1.pow_mod_ref(d, n).unwrap())
            * Integer::from(h_1.pow_mod_ref(d_1, n).unwrap())
            * &inv_E)
            % n;
        let rhs = (Integer::from(g_2.pow_mod_ref(d, n).unwrap())
            * Integer::from(h_2.pow_mod_ref(d_2, n).unwrap())
            * &inv_F)
            % n;

        let str = lhs.to_string() + &rhs.to_string();
        let hash = <H as Digest>::digest(str);
        let output = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        challenge == &output
    }

    /* Algorithm 3 Proof of Square */
    fn proof_of_square<H>(
        x: &Integer,
        r_1: &Integer,
        g: &Integer,
        h: &Integer,
        E: &Integer,
        l: u32,
        t: u32,
        b: &Integer,
        s: u32,
        s1: u32,
        s2: u32,
        n: &Integer,
    ) -> ProofOfS
    where
        H: Digest,
    {
        let r_2 = rand_int(
            -Integer::from(2).pow(s) * n + Integer::from(1),
            Integer::from(2).pow(s) * n - Integer::from(1),
        );
        let F = (Integer::from(g.pow_mod_ref(x, n).unwrap())
            * Integer::from(h.pow_mod_ref(&r_2, n).unwrap()))
            % n;
        let r_3 = r_1 - (&r_2 * x).complete();

        let proof_ss = Self::proof_same_secret::<H>(x, &r_2, &r_3, g, h, &F, h, l, t, b, s1, s2, n);
        // proof_of_s = {'E': int(E), 'F': int(F), 'proof_ss': proof_ss}
        ProofOfS {
            E: E.clone(),
            F,
            proof_ss,
        }
    }

    /* Algorithm 4 Verify Proof of Square */
    fn verify_of_square<H>(proof_of_s: &ProofOfS, g: &Integer, h: &Integer, n: &Integer) -> bool
    where
        H: Digest,
    {
        Self::verify_same_secret::<H>(
            &proof_of_s.F,
            &proof_of_s.E,
            g,
            h,
            &proof_of_s.F,
            h,
            n,
            &proof_of_s.proof_ss,
        )
    }

    /* Algorithm 5 Proof of Larger Interval Specific factor 2 ** T */
    fn proof_large_interval_specific<H>(
        x: &Integer,
        r: &Integer,
        g: &Integer,
        h: &Integer,
        t: u32,
        l: u32,
        b: &Integer,
        s: u32,
        n: &Integer,
        T: u32,
    ) -> ProofLi
    where
        H: Digest,
    {
        let mut boolean = true;
        let mut C = Integer::from(0);
        let mut D_1 = Integer::from(0);
        let mut D_2 = Integer::from(0);

        while boolean {
            let w = rand_int(
                Integer::from(0),
                (Integer::from(2).pow(T) * Integer::from(2).pow(t + l)) * b - Integer::from(1),
            );
            let nu = rand_int(
                -(Integer::from(2).pow(T) * Integer::from(2).pow(t + l + s)) * n + Integer::from(1),
                (Integer::from(2).pow(T) * Integer::from(2).pow(t + l + s)) * n - Integer::from(1),
            );
            let omega = (Integer::from(g.pow_mod_ref(&w, n).unwrap())
                * Integer::from(h.pow_mod_ref(&nu, n).unwrap()))
                % n;

            let str = omega.to_string();
            let hash = <H as Digest>::digest(str);
            C = Integer::from_digits(hash.as_slice(), Order::MsfBe);

            let c = &C % (Integer::from(2).pow(t));

            D_1 = w + (x * &c);
            D_2 = nu + (r * &c);

            if c * b <= D_1
                && D_1
                    <= (Integer::from(2).pow(T) * Integer::from(2).pow(t + l)) * b
                        - Integer::from(1)
            {
                boolean = false;
            }
        }

        // proof_li = {'C': int(C), 'D_1': int(D_1), 'D_2': int(D_2)}
        ProofLi { C, D_1, D_2 }
    }

    /* Algorithm 6 Verify Proof of Larger Interval Specific factor 2 ** T */
    fn verify_large_interval_specific<H>(
        proof_li: &ProofLi,
        E: &Integer,
        g: &Integer,
        h: &Integer,
        n: &Integer,
        t: u32,
        l: u32,
        b: &Integer,
        T: u32,
    ) -> bool
    where
        H: Digest,
    {
        let ProofLi { C, D_1, D_2 } = proof_li;
        let c = C % (Integer::from(2).pow(t));
        let inv_E = Integer::from(E.pow_mod_ref(&(-Integer::from(1) * &c), n).unwrap());
        let commit = (Integer::from(g.pow_mod_ref(D_1, n).unwrap())
            * Integer::from(h.pow_mod_ref(D_2, n).unwrap())
            * &inv_E)
            % n;

        let str = commit.to_string();
        let hash = <H as Digest>::digest(str);
        let output = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        if &(c * Integer::from(b)) <= D_1
            && D_1
                <= &(Integer::from(2).pow(T) * (Integer::from(2).pow(t + l) * b - Integer::from(1)))
            && C == &output
        {
            return true;
        }

        false
    }

    /* Algorithm 7 Proof with Tolerance Specific factor 2 ** T */
    fn proof_of_tolerance_specific<H>(
        x: Integer,
        r: Integer,
        g: &Integer,
        h: &Integer,
        n: &Integer,
        a: &Integer,
        b: &Integer,
        t: u32,
        l: u32,
        s: u32,
        s1: u32,
        s2: u32,
        T: u32,
    ) -> ProofWt
    where
        H: Digest,
    {
        /* # NOTE: the first step of this algorithm (see Section 3.1.1 in [Boudot2000])
        #       requires a proof of knowledge of x and r related to the Commitment E = g**x * h**r % n
        #       (i.e., NON-Interactive Sigma protocol of Two secrets - nisp2sec).
        #       We SKIP such Sigma protocol, assuming that this PoK was already done before the range proof. */

        let aa = Integer::from(2).pow(T) * Integer::from(a)
            - Integer::from(2).pow(l + t + rug::ops::DivRounding::div_floor(T, 2) + 1)
                * Integer::from(Integer::from(b - a).sqrt_ref());

        let bb = Integer::from(2).pow(T) * Integer::from(b)
            + Integer::from(2).pow(l + t + rug::ops::DivRounding::div_floor(T, 2) + 1)
                * Integer::from(Integer::from(b - a).sqrt_ref());

        let x_a = &x - aa;

        let x_b = bb - &x;

        let x_a_1 = Integer::from(x_a.sqrt_ref());
        let x_a_2 = x_a - x_a_1.clone().pow(2);

        let x_b_1 = Integer::from(x_b.sqrt_ref());
        let x_b_2 = x_b - x_b_1.clone().pow(2);

        let mut boolean = true;
        let mut r_a_1 = Integer::from(1);
        let mut r_a_2 = Integer::from(1);
        while boolean {
            r_a_1 = rand_int(
                -Integer::from(2).pow(s) * Integer::from(2).pow(T) * n + Integer::from(1),
                Integer::from(2).pow(s) * Integer::from(2).pow(T) * n - Integer::from(1),
            );
            r_a_2 = (&r - &r_a_1).complete();
            if -Integer::from(2).pow(s) * Integer::from(2).pow(T) * n + Integer::from(1) <= r_a_2
                && r_a_2 <= Integer::from(2).pow(s) * Integer::from(2).pow(T) * n - Integer::from(1)
                && r == (&r_a_1 + &r_a_2).complete()
            {
                boolean = false;
            }
        }

        let mut r_b_1 = Integer::from(1);
        let mut r_b_2 = Integer::from(1);

        boolean = true;
        while boolean {
            r_b_1 = rand_int(
                -Integer::from(2).pow(s) * Integer::from(2).pow(T) * n + Integer::from(1),
                Integer::from(2).pow(s) * Integer::from(2).pow(T) * n - Integer::from(1),
            );
            r_b_2 = (-Integer::from(1)) * &r - &r_b_1;
            if -Integer::from(2).pow(s) * Integer::from(2).pow(T) * n + Integer::from(1) <= r_b_2
                && r_b_2 <= Integer::from(2).pow(s) * Integer::from(2).pow(T) * n - Integer::from(1)
                && (-Integer::from(1)) * &r == (&r_b_1 + &r_b_2).complete()
            {
                boolean = false;
            }
        }

        let E_a_1 = (Integer::from(g.pow_mod_ref(&x_a_1.clone().pow(2), n).unwrap())
            * Integer::from(h.pow_mod_ref(&r_a_1, n).unwrap()))
            % n;
        let E_a_2 = (Integer::from(g.pow_mod_ref(&x_a_2, n).unwrap())
            * Integer::from(h.pow_mod_ref(&r_a_2, n).unwrap()))
            % n;

        let E_b_1 = (Integer::from(g.pow_mod_ref(&x_b_1.clone().pow(2), n).unwrap())
            * Integer::from(h.pow_mod_ref(&r_b_1, n).unwrap()))
            % n;
        let E_b_2 = (Integer::from(g.pow_mod_ref(&x_b_2, n).unwrap())
            * Integer::from(h.pow_mod_ref(&r_b_2, n).unwrap()))
            % n;

        let proof_of_square_a =
            Self::proof_of_square::<H>(&x_a_1, &r_a_1, g, h, &E_a_1, l, t, b, s, s1, s2, n);
        let proof_of_square_b =
            Self::proof_of_square::<H>(&x_b_1, &r_b_1, g, h, &E_b_1, l, t, b, s, s1, s2, n);
        let proof_large_i_a =
            Self::proof_large_interval_specific::<H>(&x_a_2, &r_a_2, g, h, t, l, b, s, n, T);
        let proof_large_i_b =
            Self::proof_large_interval_specific::<H>(&x_b_2, &r_b_2, g, h, t, l, b, s, n, T);

        // proof_wt = {
        //     'E_a_1': int(E_a_1), 'E_a_2': int(E_a_2), 'E_b_1': int(E_b_1), 'E_b_2': int(E_b_2),
        //     'proof_of_square_a': proof_of_square_a, 'proof_of_square_b': proof_of_square_b,
        //     'proof_large_i_a': proof_large_i_a, 'proof_large_i_b': proof_large_i_b
        // }

        ProofWt {
            E_a_1,
            E_a_2,
            E_b_1,
            E_b_2,
            proof_of_square_a,
            proof_of_square_b,
            proof_large_i_a,
            proof_large_i_b,
        }
    }

    /* Algorithm 8 Verify Proof with Tolerance Specific factor 2 ** T */
    fn verify_of_tolerance_specific<H>(
        proof_wt: &ProofWt,
        g: &Integer,
        h: &Integer,
        E: &Integer,
        n: &Integer,
        a: &Integer,
        b: &Integer,
        t: u32,
        l: u32,
        T: u32,
    ) -> bool
    where
        H: Digest,
    {
        let aa = Integer::from(2).pow(T) * Integer::from(a)
            - Integer::from(2).pow(l + t + rug::ops::DivRounding::div_floor(T, 2) + 1)
                * Integer::from(Integer::from(b - a).sqrt_ref());
        let bb = Integer::from(2).pow(T) * Integer::from(b)
            + Integer::from(2).pow(l + t + rug::ops::DivRounding::div_floor(T, 2) + 1)
                * Integer::from(Integer::from(b - a).sqrt_ref());
        let E_a = divm(E, &Integer::from(g.pow_mod_ref(&aa, n).unwrap()), n);
        let E_b = divm(&Integer::from(g.pow_mod_ref(&bb, n).unwrap()), E, n);
        // NOTE: E_a and E_b must be recomputed during the verification,
        //        see Section 3.1.1 in [Boudot2000] ("Both Alice and Bob compute...")

        let ProofWt {
            E_a_1,
            E_a_2,
            E_b_1,
            E_b_2,
            proof_of_square_a,
            proof_of_square_b,
            proof_large_i_a,
            proof_large_i_b,
        } = proof_wt;

        let div_a = divm(&E_a, E_a_1, n);
        let div_b = divm(&E_b, E_b_1, n);

        if E_a_2 == &div_a && E_b_2 == &div_b {
            let b_s = Self::verify_of_square::<H>(proof_of_square_a, g, h, n)
                && Self::verify_of_square::<H>(proof_of_square_b, g, h, n);
            let b_li = Self::verify_large_interval_specific::<H>(
                proof_large_i_a,
                E_a_2,
                g,
                h,
                n,
                t,
                l,
                b,
                T,
            ) && Self::verify_large_interval_specific::<H>(
                proof_large_i_b,
                E_b_2,
                g,
                h,
                n,
                t,
                l,
                b,
                T,
            );
            return b_s && b_li;
        }

        false
    }

    /* Algorithm 9 Square Decomposition Range Proof (i.e. Proof without tolerance) from [Boudot2000] on section 3.1.2 */
    fn proof_of_square_decomposition_range<H>(
        x: &Integer,
        r: &Integer,
        g: &Integer,
        h: &Integer,
        E: &Integer,
        n: &Integer,
        a: &Integer,
        b: &Integer,
        t: u32,
        l: u32,
        s: u32,
        s1: u32,
        s2: u32,
        T: u32,
    ) -> Self
    where
        H: Digest,
    {
        let x_prime = Integer::from(2).pow(T) * x;
        let r_prime = Integer::from(2).pow(T) * r;

        let E_prime = Integer::from(E.pow_mod_ref(&(Integer::from(2).pow(T)), n).unwrap());

        let proof_of_tolerance = Self::proof_of_tolerance_specific::<H>(
            x_prime, r_prime, g, h, n, a, b, t, l, s, s1, s2, T,
        );

        Self {
            proof_of_tolerance,
            E_prime,
            E: E.clone(),
        }
    }

    /* Algorithm 10 Verify Square Decomposition Range Proof (i.e. Proof without tolerance) from [Boudot2000] on section 3.1.2 */
    fn verify_of_square_decomposition_range<H>(
        &self,
        g: &Integer,
        h: &Integer,
        n: &Integer,
        a: &Integer,
        b: &Integer,
        t: u32,
        l: u32,
        T: u32,
    ) -> bool
    where
        H: Digest,
    {
        if self.E_prime == Integer::from(self.E.pow_mod_ref(&Integer::from(2).pow(T), n).unwrap()) {
            let res_verify_ts = Self::verify_of_tolerance_specific::<H>(
                &self.proof_of_tolerance,
                g,
                h,
                &self.E_prime,
                n,
                a,
                b,
                t,
                l,
                T,
            );
            return res_verify_ts;
        }
        return false;
    }

    pub fn prove<H>(
        value: &Integer,
        commitment: &CL03Commitment,
        base1: &Integer,
        base2: &Integer,
        module: &Integer,
        rmin: &Integer,
        rmax: &Integer,
    ) -> Self
    where
        H: Digest,
    {
        if rmax <= rmin {
            panic!("rmin > rmax");
        }

        let T = 2 * (Self::t + Self::l + 1) + ((rmax - rmin).complete().significant_bits());
        let proof_of_sdr = Self::proof_of_square_decomposition_range::<H>(
            value,
            &commitment.randomness,
            base1,
            base2,
            &commitment.value,
            module,
            rmin,
            rmax,
            Self::t,
            Self::l,
            Self::s,
            Self::s1,
            Self::s2,
            T,
        );
        proof_of_sdr
    }

    pub fn verify<H>(
        &self,
        base1: &Integer,
        base2: &Integer,
        module: &Integer,
        rmin: &Integer,
        rmax: &Integer,
    ) -> bool
    where
        H: Digest,
    {
        if rmax <= rmin {
            panic!("rmin > rmax");
        }

        let T = 2 * (Self::t + Self::l + 1) + ((rmax - rmin).complete().significant_bits());

        let valid = Self::verify_of_square_decomposition_range::<H>(
            self,
            base1,
            base2,
            module,
            rmin,
            rmax,
            Self::t,
            Self::l,
            T,
        );
        valid
    }
}
