use super::*;
use crate::context::Context;
use crate::context::RistrettoCtx as Ctx;
use crate::traits::{element::GroupElement, group::CryptoGroup, scalar::GroupScalar};
use crate::utils::serialization::{VDeserializable, VSerializable};

#[test]
fn test_ristretto_scalar_negation() {
    let s1 = Ctx::random_scalar();
    let s_neg = s1.neg();

    assert_eq!(
        s_neg.add(&s1),
        RistrettoScalar::zero(),
        "Negation property s + (-s) = 0 failed"
    );
}

#[test]
fn test_ristretto_scalar_inversion() {
    let s = Ctx::random_scalar();

    if s != RistrettoScalar::zero() {
        let s_inv = s.inv().expect("Scalar inversion failed");
        let product = s.mul(&s_inv);
        assert_eq!(
            product,
            RistrettoScalar::one(),
            "s * s_inv = 1 property failed"
        );
    }

    let zero = RistrettoScalar::zero();
    assert!(zero.inv().is_none(), "Inversion of zero must be None");
}

#[test]
fn test_ristretto_power_product() {
    let s1 = Ctx::random_scalar();
    let s2 = Ctx::random_scalar();
    let g = Ctx::generator();

    let e1 = g.exp(&s1);
    let e2 = g.exp(&s2);
    let e3_sum = e1.mul(&e2);

    let s_sum = s1.add(&s2);
    let e3_expected = g.exp(&s_sum);

    assert_eq!(
        e3_sum, e3_expected,
        "Element addition failed: e1+e2 != (s1+s2)*G"
    );
}

#[test]
fn test_ristretto_element_inv() {
    let s = Ctx::random_scalar();
    let g = Ctx::generator();
    let e = g.exp(&s);

    let e_neg = e.inv();
    let e_plus_e_neg = e.mul(&e_neg);

    assert_eq!(
        e_plus_e_neg,
        RistrettoElement::one(),
        "Element negation failed: e + (-e) != Id"
    );

    let s_neg = s.neg();
    let e_neg_expected = g.exp(&s_neg);
    assert_eq!(
        e_neg, e_neg_expected,
        "Element negation failed: (-s)*G != -(s*G)"
    );
}

#[test]
fn test_ristretto_power_power() {
    let s1 = Ctx::random_scalar();
    let s2 = Ctx::random_scalar();
    let g = Ctx::generator();

    let e1 = g.exp(&s1);
    let e2 = e1.exp(&s2);

    let s_prod = s1.mul(&s2);
    let e_expected = g.exp(&s_prod);

    assert_eq!(e2, e_expected, "Element scalar multiplication failed");
}

#[test]
fn test_ristretto_element_identity_properties() {
    let s = Ctx::random_scalar();
    let g = Ctx::generator();
    let e = g.exp(&s);
    let id = RistrettoElement::one();

    assert_eq!(e.mul(&id), e, "e + Id != e");
    assert_eq!(id.mul(&e), e, "Id + e != e");

    let zero_scalar = RistrettoScalar::zero();
    assert_eq!(g.exp(&zero_scalar), id, "G^0 != Id");
}

#[test]
fn test_ristretto_element_mul_commutativity() {
    let e1 = Ctx::random_element();
    let e2 = Ctx::random_element();

    let sum1 = e1.mul(&e2);
    let sum2 = e2.mul(&e1);

    assert_eq!(sum1, sum2, "Element multiplication is not commutative");
}

#[test]
fn test_ristretto_element_mul_associativity() {
    let e1 = Ctx::random_element();
    let e2 = Ctx::random_element();
    let e3 = Ctx::random_element();

    let sum_left_assoc = (e1.mul(&e2)).mul(&e3);
    let sum_right_assoc = e1.mul(&(e2.mul(&e3)));

    assert_eq!(
        sum_left_assoc, sum_right_assoc,
        "Element multiplication is not associative"
    );
}

#[test]
fn test_ristretto_scalar_element_exp_distributivity() {
    let s_op = Ctx::random_scalar();

    let e1 = Ctx::random_element();
    let e2 = Ctx::random_element();

    // (e1 * e2)^s
    let sum_elements = e1.mul(&e2);
    let lhs = sum_elements.exp(&s_op);

    // (e1^s) * (e2^s)
    let term1 = e1.exp(&s_op);
    let term2 = e2.exp(&s_op);
    let rhs = term1.mul(&term2);

    assert_eq!(lhs, rhs, "Distributivity (e1*e2)^s = e1^s * e2^s failed");
}

#[test]
fn test_ristretto_scalar_element_mul_distributivity() {
    let s1 = Ctx::random_scalar();
    let s2 = Ctx::random_scalar();

    let e = Ctx::random_element();

    let sum_scalars = s1.add(&s2);
    let lhs = e.exp(&sum_scalars);

    let term1 = e.exp(&s1);
    let term2 = e.exp(&s2);
    let rhs = term1.mul(&term2);

    assert_eq!(lhs, rhs, "Distributivity e^(s1+s2) = e^s1 + e^s2 failed");
}

#[test]
fn test_ristretto_group_hash_to_scalar() {
    let input1 = b"some input data";
    let input2 = b"other input data";
    let ds_tag = b"ds tag";

    let s1 = Ristretto255Group::hash_to_scalar(&[input1], &[ds_tag]);
    // Same input, same output
    let s2 = Ristretto255Group::hash_to_scalar(&[input1], &[ds_tag]);
    // Different input, different output
    let s3 = Ristretto255Group::hash_to_scalar(&[input2], &[ds_tag]);

    assert_eq!(s1, s2, "Hash to scalar not equal for equal input");
    assert_ne!(
        s1, s3,
        "Hash to scalar produces same output for different inputs"
    );
}

#[test]
fn test_ristretto_element_serialization() {
    let s = Ctx::random_scalar();
    let g = Ctx::generator();
    let e_orig = g.exp(&s);

    let serialized_e = e_orig.ser();
    assert_eq!(serialized_e.len(), 32, "Serialized element length mismatch");

    let e_deserialized =
        RistrettoElement::deser(&serialized_e).expect("Element deserialization failed");
    assert_eq!(
        e_orig, e_deserialized,
        "Original and deserialized elements do not match"
    );

    // Test identity
    let e_id = RistrettoElement::one();
    let ser_id = e_id.ser();
    let des_id = RistrettoElement::deser(&ser_id).unwrap();
    assert_eq!(e_id, des_id);
}

#[test]
fn test_ristretto_scalar_serialization() {
    let s_orig = Ctx::random_scalar();

    let serialized_s = s_orig.ser();
    assert_eq!(serialized_s.len(), 32, "Serialized scalar length mismatch");

    let s_deserialized =
        RistrettoScalar::deser(&serialized_s).expect("Scalar deserialization failed");
    assert_eq!(
        s_orig, s_deserialized,
        "Original and deserialized scalars do not match"
    );

    let s_zero = RistrettoScalar::zero();
    let ser_zero = s_zero.ser();
    let des_zero = RistrettoScalar::deser(&ser_zero).unwrap();
    assert_eq!(s_zero, des_zero);

    let s_one = RistrettoScalar::one();
    let ser_one = s_one.ser();
    let des_one = RistrettoScalar::deser(&ser_one).unwrap();
    assert_eq!(s_one, des_one);
}
