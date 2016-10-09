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
Print ack.
Check ack.

(* Compute some values *)
Eval compute in ack 1 0. (* 2 *)
Eval compute in ack 1 1. (* 3 *)
Eval compute in ack 2 0. (* 3 *)

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
  rewrite <- Nat.add_assoc, <- Nat.add_assoc.
  trivial.
Qed.

(* Prove that A(3, n) = 2^(n + 3) - 3 *)
Theorem ack_three:
  forall n: nat, ack 3 n = Nat.pow 2 (n + 3) - 3.
Proof.
  induction n. trivial.
  rewrite ack_recursive, ack_two, IHn.
  rewrite Nat.mul_sub_distr_l.
  rewrite <- (Nat.pow_succ_r _ _ (Nat.le_0_l (n + 3))).
  symmetry.
  apply Nat.add_sub_eq_l.
  rewrite Nat.add_comm.
  rewrite <- Nat.add_assoc.
  apply Nat.sub_add.
  (* Now, need to prove 3 + 3 <= Nat.pow 2 (S n + 3) *)
  apply (Nat.le_trans _ (Nat.pow 2 3)).
    apply (Nat.le_trans 6 7 8); auto.
    rewrite (Nat.add_comm (S n) 3).
    apply Nat.pow_le_mono_r; auto.
    rewrite <- (Nat.add_0_r 3).
    apply Nat.add_le_mono_l, Nat.le_0_l.
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
  ack 4 1 = (Nat.pow 2 16) - 3.
Proof.
  rewrite ack_recursive, ack_4_0, ack_three.
  trivial.
Qed.

Lemma pow_eq_exponent:
  forall b e e': nat, e = e' -> Nat.pow b e = Nat.pow b e'.
Proof.
  intros b e e' H.
  rewrite H.
  trivial.
Qed.

(* This takes too much time on Coq versions which expand numbers *)
(*
Theorem ack_4_2:
  ack 4 2 = (Nat.pow 2 (Nat.pow 2 16)) - 3.
Proof.
  rewrite ack_recursive, ack_4_1, ack_three.
  apply Nat.add_sub_eq_l.
  rewrite Nat.sub_add.
    Focus 2.
    apply (Nat.le_trans 3 (Nat.pow 2 2) (Nat.pow 2 16)).
      simpl; auto.
      apply Nat.pow_le_mono_r; auto.
      apply Nat.leb_le; auto.

  rewrite Nat.add_comm.
  rewrite Nat.sub_add.
   apply pow_eq_exponent. apply pow_eq_exponent. trivial.

  apply (Nat.le_trans 3 (Nat.pow 2 2)).
    simpl; auto.
  apply Nat.pow_le_mono_r; auto.
  apply (Nat.le_trans 2 (Nat.pow 2 1) (Nat.pow 2 16)).
    auto.
    apply Nat.pow_le_mono_r; auto.
    apply Nat.leb_le; auto.
Qed.
*)

(* Enumerate everything that were just proved *)
SearchAbout ack.
