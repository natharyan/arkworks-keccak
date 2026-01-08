<!-- Multiplying a witness FpVar by a constant FpVar (created with FpVar::new_constant or by constant-folding) does NOT create a multiplication gate — it becomes a linear combination (free).
Multiplying a witness by a non‑constant FpVar (another witness or a public input) DOES create a multiplication constraint. -->


fn mul_helper<F: PrimeField>(
    a: &FpVar<F>, // witness or input
    b: &FpVar<F>, // could be constant or not
) -> FpVar<F> {
    a * b
}

fn main() {
    let cs: ConstraintSystem<Fq> = ConstraintSystem::new_ref();
    // witness variable
    let a = FpVar::new_witness(cs.clone(), || Ok(Fq::from(3u64))).unwrap();
    // constant variable
    let c = FpVar::new_constant(cs.clone(), Fq::from(5u64)).unwrap();
    let before = cs.num_constraints();
    let _ = mul_helper(&a, &c);
    assert_eq!(before, cs.num_constraints(), "no new constraints when multiplying by constant");

    // non-constant input
    let b = FpVar::new_input(cs.clone(), || Ok(Fq::from(7u64))).unwrap();
    let before = cs.num_constraints();
    let _ = mul_helper(&a, &b);
    assert!(cs.num_constraints() > before, "multiplying two non-constant vars adds constraints");
}