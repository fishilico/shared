(* Prove a few things on Ackermann function, which is defined by:
 *   A(0, n) = n+1
 *   A(m+1, 0) = A(m, 1)
 *   A(m+1, n+1) = A(m, A(m+1, n))
 *
 * Wikipedia article: https://en.wikipedia.org/wiki/Ackermann_function
 *)

Require Import NPeano.

Fixpoint ack (m: nat) : nat -> nat :=
  match m with
    | O => S
    | S m' => fix ack_m (n: nat) : nat :=
      match n with
        | O => ack m' 1
        | S n' => ack m' (ack_m n')
      end
  end
.

(* Display the definition in Frama-C window *)
Check ack.
Print ack.

(* Compute some values *)
Eval compute in ack 1 0.
Eval compute in ack 1 1.
Eval compute in ack 2 0.

(* Prove the 3 recursive relations of the definition *)
Lemma ack_zero:
  forall n: nat, ack O n = n + 1.
Proof.
  intro n.
  unfold ack.
  rewrite <- (plus_n_Sm n O).
  auto.
Qed.

Lemma ack_m_zero:
  forall m: nat, ack (S m) O = ack m 1.
Proof.
  trivial.
Qed.

Lemma ack_recursive:
  forall m n: nat, ack (S m) (S n) = ack m (ack (S m) n).
Proof.
  trivial.
Qed.

(* Prove that A(1, n) = n + 2 *)
Theorem ack_one:
  forall n: nat, ack 1 n = n + 2.
Proof.
  induction n. trivial.
  rewrite ack_recursive.
  rewrite IHn.
  trivial.
Qed.

(* Prove that A(2, n) = 2 * n + 3 *)
Theorem ack_two:
  forall n: nat, ack 2 n = 2 * n + 3.
Proof.
  induction n. trivial.
  rewrite ack_recursive.
  rewrite ack_one.
  rewrite IHn.
  rewrite <- mult_n_Sm.
  rewrite <- NPeano.Nat.add_assoc.
  rewrite <- NPeano.Nat.add_assoc.
  trivial.
Qed.


(* Define pow function for Ackermann(3, ...) *)
Definition pow (b: nat) : nat -> nat :=
  fix pow_b (e: nat) : nat :=
    match e with
      | O => 1
      | S e' => (pow_b e') * b
    end
.

Lemma pow_mult_l:
  forall b e: nat, b * (pow b e) = pow b (S e).
Proof.
  intros b e.
  rewrite Nat.mul_comm.
  trivial.
Qed.

Lemma pow_eq_exponent:
  forall b e e': nat, e = e' -> pow b e = pow b e'.
Proof.
  intros b e e' H.
  rewrite H.
  trivial.
Qed.

Lemma pow_S_exponent:
  forall b, 1 <= b -> forall e: nat, pow b e <= pow b (S e).
Proof.
  intros b Hb e.
  rewrite <- (NPeano.Nat.mul_1_r (pow b e)).
  apply Nat.mul_le_mono_l.
  trivial.
Qed.

Lemma pow_increase_exponent:
  forall b : nat, 1 <= b -> forall e e': nat, pow b e <= pow b (e + e').
Proof.
  intros b Hb e.
  induction e'.
    rewrite Nat.add_0_r. trivial.
  rewrite <- Peano.plus_n_Sm.
  apply (Nat.le_trans (pow b e) (pow b (e + e'))).
    trivial.
    apply (pow_S_exponent b Hb).
Qed.

Lemma pow_le_exponent:
  forall b : nat, 1 <= b -> forall e e': nat, e <= e' -> pow b e <= pow b e'.
Proof.
  intros b Hb e e' He.
  rewrite <- (Nat.sub_add e e'); trivial.
  rewrite Nat.add_comm.
  apply (pow_increase_exponent b Hb).
Qed.

(* Prove that A(3, n) = 2^(n + 3) - 3 *)
Theorem ack_three:
  forall n: nat, ack 3 n = pow 2 (n + 3) - 3.
Proof.
  induction n. trivial.
  rewrite ack_recursive, ack_two, IHn.
  rewrite NPeano.Nat.mul_sub_distr_l.
  rewrite pow_mult_l.
  symmetry.
  apply NPeano.Nat.add_sub_eq_l.
  rewrite NPeano.Nat.add_comm.
  rewrite <- NPeano.Nat.add_assoc.
  apply NPeano.Nat.sub_add.
  (* Now, need to prove 6 <= pow 2 (S n + 3) *)
  apply (Nat.le_trans 6 (pow 2 3)).
    apply (Nat.le_trans 6 7 8); auto.
    rewrite (NPeano.Nat.add_comm (S n) 3). apply pow_increase_exponent. auto.
Qed.

(* A(4, 0) = A(3, 1) = 13
 * A(4, 1) = A(3, 13) = 65533
 * A(4, 2) = A(3, 65533) = 2^65536 - 3
 *
 * A(5, 0) = A(4, 1) = 65533
 * A(5, 1) = A(4, 65533)
 *
 * Let's prove A(4, n) values for n = 0, 1, 2
 *)
Theorem ack_4_0:
  ack 4 0 = 13.
Proof.
  trivial.
Qed.

Theorem ack_4_1:
  ack 4 1 = (pow 2 16) - 3.
Proof.
  rewrite ack_recursive, ack_4_0, ack_three.
  trivial.
Qed.

Theorem ack_4_2:
  ack 4 2 = (pow 2 (pow 2 16)) - 3.
Proof.
  rewrite ack_recursive, ack_4_1, ack_three.
  apply Nat.add_sub_eq_l.
  rewrite NPeano.Nat.sub_add.
    rewrite NPeano.Nat.add_comm.
    rewrite NPeano.Nat.sub_add.
      apply pow_eq_exponent. apply pow_eq_exponent. trivial.

      apply (Nat.le_trans 3 (pow 2 2)).
        simpl; auto.
        apply pow_increase_exponent; auto.

    apply (Nat.le_trans 3 (pow 2 2) (pow 2 16)).
      simpl; auto.
      apply pow_le_exponent; auto with *.
Qed.

(* Enumerate everything that were just proved *)
SearchAbout ack.
