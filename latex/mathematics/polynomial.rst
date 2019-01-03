Polynomial
==========

.. role:: latex(raw)
     :format: latex

Definitions
-----------

Let :latex:`$(F, +, \times)$` be a field.
By adding a new object to the set of scalars :latex:`$F$`, named *the unknown*, :latex:`$X$`, and making a ring out of it, a new set can be built.
This set can be seen as a :latex:`$F$`-vector space, with a multiplication operation on vectors too.

.. raw:: latex

    \begin{definition}[Polynomial]
      A polynomial is a linear combination with coefficients in a field $F$ and vectors being the powers of the unknown $X$ (with $X^0 = 1_F$).
      The set of polynomials is named $F[X]$.
    \end{definition}

Operations on :latex:`$P, Q, R \in F[X]$`:

* The addition is extended and remains associative (:latex:`$(P + Q) + R = P + (Q + R)$`) and commutative (:latex:`$P + Q = Q + P$`).
* The multiplication is extended and remains associative (:latex:`$(P \times Q) \times R = P \times (Q \times R)$`) and commutative (:latex:`$P \times Q = Q \times P$`).
* :latex:`$0_F$` remains the neutral item for the addition and :latex:`$1_F$` the one for the multiplication.
* Distributivity remains (:latex:`$(P + Q) \times R = (P \times R) + (Q \times R)$`)
* The addition is still inversible, with :latex:`$-P = (-1_F) \times P$`
* The multiplication is no longer inversible, as :latex:`$X$` does not have an inverse.

To conclude, :latex:`$(F[X], +, \times)$` is an commutative ring.

There is nontheless a useful property of the multiplication:

.. raw:: latex

    \begin{theorem}[Null product]
      \begin{displaymath}
        \forall P, Q \in F[X], PQ = 0 \Leftrightarrow P = 0 \lor Q = 0
      \end{displaymath}
    \end{theorem}

    This theorem can be proven using the larger power of $X$ in both $P$ and $Q$.


By definition, :latex:`$F[X]$` is also a :latex:`$F$`-vector space spanned from the monomials:

.. raw:: latex

    \begin{displaymath}
      F[X] = \text{span}(1, X, X^2, ...)
    \end{displaymath}

    By construction,
    \begin{itemize}
      \item $X \notin F = \text{span}(1)$
      \item $X^2 \notin \text{span}(1, X)$
      \item $X^3 \notin \text{span}(1, X, X^2)$
      \item etc.
    \end{itemize}
    Therefore $\{1, X, X^2, ...\}$ is a basis of the $F$-vector space of polinomials $F[X]$.
    It is called the canonical basis of polynomials.
    The coordinates of polynomials in this basis constitute the coefficients of the polynomial.
    They make an almost empty sequence of scalars of $F$.

    \begin{definition}[Degree]
      The degree of a polynomial $P \neq 0$ is the maximum exponent of $X$ for which the coefficient is not zero.
      With $P = \sum_i p_i X^i$,
      \begin{displaymath}
        \deg(P) = \max\{i \in \N, p_i \neq 0\}
      \end{displaymath}
    \end{definition}

    Properties when the argument of $\deg$ is not zero:
    \begin{itemize}
      \item $\forall n \in \N, \deg(X^n) = n$
      \item $\deg(P + Q) \leq \max(\deg(P), \deg(Q))$
      \item $\deg(PQ) = \deg(P) + \deg(Q)$
      \item $\forall \lambda \in F\backslash\{0\}, \deg(\lambda P) = \deg(P)$
    \end{itemize}

    To simplify computations, $\deg(0)$ can be defined.
    Its value needs to satify:
    \begin{itemize}
      \item $\deg(0) = \deg(1 + (-1)) \leq \max(\deg(1), \deg(-1)) = 0$
      \item $\forall P \in F[X], \deg(0) = \deg(0P) = \deg(0) + \deg(P)$
    \end{itemize}
    These two relationships are compatible when extending the defition of $\deg$ with:
    \begin{equation}
      \deg(0) = -\infty
    \end{equation}

    This adds a nice property: $\deg(P) \leq 0 \Leftrightarrow P \in F$

    \begin{definition}[Polynomials by degree]
      For $d \in \N$, $F_d[X]$ is defined as the set of polynomials of degree at most $d$.
    \end{definition}
    $F_d[X]$ is a $F$-vector subspace of $F[X]$, but not a ring as $X^d . X \notin F_d[X]$

    \begin{definition}[Polynomial function]
      With a polynomial $P$, it is possible to define a function $F \rightarrow F$ which associates a scalar $x \in F$ with the value obtained by replacing $X$ by $x$ in $P$.
      By language abuse, this function may share the name $P$, and $P(x)$ is the value of this function for $x$.
    \end{definition}
    \begin{theorem}[Linearity of the polynomial function transformation]
      The following function is a linear mapping between polynomials and the set of functions $F \rightarrow F$ (which are both $F$-vector spaces):
      \begin{eqnarray*}
        F[X] &\rightarrow& \mathcal{F}(F, F) \\
        P &\mapsto& (x \mapsto P(x))
      \end{eqnarray*}
    \end{theorem}

    \begin{definition}[Root]
      A scalar $r \in F$ is said to be a root of polynomial $P \in F[X]$ if $P(r) = 0$.
    \end{definition}


Division
--------

Euclidean division
~~~~~~~~~~~~~~~~~~

.. raw:: latex

    $X$ is not invertible in $F[X]$ (this can be show using $\deg(PQ) = \deg(P) + \deg(Q)$ and $\deg(1) = 0$).
    This looks like the set of natural integers ($\N$), where numbers are not invertible.
    By similarity it is possible to define an Euclidean division between $A$ and $B$.
    This division is substracting from $A$ several multiples of $B$ until it is no longer possible.
    So long that the remainder has a degree greater of equal to those of $B$, the degree of the remainder can be decreased.

    \begin{theorem}[Euclidean division]
      \begin{equation}
        \forall A \in F[X], \forall B \in F[X]\backslash\{0\}, \exists! (Q, R) \in F[X]^2, \\
        \left\{
          \begin{array}{c}
            \deg(R) < \deg(B) \\
            A = BQ + R
          \end{array}
        \right.
      \end{equation}
      $Q$ is the quotient of the division of $A$ by $B$ and $R$ the remainder.
    \end{theorem}

    The uniqueness property comes from $0 = BQ + R \land \deg(R) < \deg(B) \Rightarrow Q = R = 0$

    \begin{definition}[Modulo]
      $\forall A \in F[X], \forall B \in F[X]\backslash\{0\}, A \mod B$ is the remainder of the Euclidean division of $A$ by $B$.
    \end{definition}

    \begin{definition}[Divisibility]
      $B$ is said to divide $A$ when $A$ is a multiple of $B$:
      \begin{eqnarray*}
        B | A &\Leftrightarrow& \exists Q \in F[X], A = BQ \\
        &\Leftrightarrow& A \in B.F[X] \\
        &\Leftrightarrow& (B = 0 \land A = 0) \lor (B \neq 0 \land A \mod B = 0)
      \end{eqnarray*}
    \end{definition}

    \begin{definition}[Primality]
      A polynomial $P$ is said to be prime if its only divisors are non-null scalars of $F$ and multiples of itself by non-null scalars, ie.:
      \begin{eqnarray*}
        \forall D \in F[X], D | P \Leftrightarrow D \in (F\backslash\{0\}) \cup (P.F\backslash\{0\})
      \end{eqnarray*}
    \end{definition}

    The modulo allows defining an equivalence relationchip ($P \mathcal{R}_B Q \Leftrightarrow (P - Q) \mod B = 0$), which leads to defining a set of equivalence classes.
    The function $P \mapsto P \mod B$ can also be considered as an endomorphism of the $F$-vector space $F[X]$ whose kernel is the set of multiples of $B$, which also leads to defining a set of equivalence classes  like any linear mapping.

    \begin{definition}[Quotiented set]
      With $B \in F[X]\backslash\{0\}$, $F[X]/B$ is the set of equivalence classes related to $P \mapsto P \mod B$.
      Each equivalence class has a unique polynomial of degree less than $\deg(B)$, which can be used to represent the class.
      By doing so, $F[X]/B$ is a $F$-vector subspace of $F_{\deg(B) - 1}[X]$.
      It is also a sub-ring of $F[X]$.
    \end{definition}

Greatest common divisor
~~~~~~~~~~~~~~~~~~~~~~~

.. raw:: latex

    \begin{definition}[Greatest common divisor]
      The greatest common divisor of polynomials $P$ and $Q$, $\gcd(P, Q)$, is the polynomial which has the greatest degree, divides both $P$ and $Q$, and whose greatest coefficient is $1$ (for unicity sake).
    \end{definition}

    The Euclidean algorithm can be used for polynomials to compute the GCD, starting by dividing $P$ and $Q$ by their respective greatest coefficient.

    The extented Euclidean algorithm can then be used in order to prove Bézout's identity for polynoms.

    \begin{theorem}[Bézout's identity (extented Euclidean algorithm)]
      \begin{eqnarray*}
        \forall P, Q \in F[X]\backslash\{0\}, \exists U, V \in F[X], UP + VQ = \gcd(P, Q)
      \end{eqnarray*}
    \end{theorem}

    \begin{theorem}[Bézout's identity with relatively prime polynomials]
      \begin{eqnarray*}
        \forall P, Q \in F[X]\backslash\{0\}, \gcd(P, Q) = 1 \Leftrightarrow \exists U, V \in F[X], UP + VQ = 1
      \end{eqnarray*}
    \end{theorem}

    \begin{theorem}[Euclid's lemma]
      \begin{eqnarray*}
        \forall P, A, B \in F[X]\backslash\{0\}, P \text{ is prime } \land P|AB \Rightarrow P|A \lor P|B
      \end{eqnarray*}
    \end{theorem}

    \begin{theorem}[Generalization of Euclid's lemma]
      \begin{eqnarray*}
        \forall P, A, B \in F[X]\backslash\{0\}, \gcd(P, A) = 1 \land P|AB \Rightarrow P|B
      \end{eqnarray*}
    \end{theorem}

Division and polynomial roots
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There is some useful theorems about the polynomial roots.

.. raw:: latex

    \begin{theorem}[Divisibility for polynomial root]
      $r \in F$ is a root of polynomial $P \in F[X]$ iff $(X - r)$ divides $P$.
    \end{theorem}

    This can be easily proved by considering the Euclidean division of $P$ by $(X - r)$.
    Let's define $R = P \mod (X - r)$ and $Q$ such that $P = (X - r)Q + R$.
    As $\deg(R) < \deg(X - r) = 1$, $R \in F$.
    Therefore:
    \begin{displaymath}
      P(r) = ((X - r)Q + R)(r) = 0.Q(r) + R = R
    \end{displaymath}
    $r$ is a root of $P$ iff $P(r) = 0$, iff $R = 0$, iff $P \mod (X - r) = 0$.

QED.

It follows that prime polynomials of degree larger than 1 do not have any root.

.. raw:: latex

    \begin{theorem}[Lagrange theorem on polynomials]
      A non-null polynomial $P \in F[X]\backslash\{0\}$ has at most $\deg(P)$ roots.
    \end{theorem}
    Proof: if there were more, $P$ would be a multiple of the product of all the $(X - r)$ polynomials, which degree would be greater that $P$'s.


Galois fields over prime polynomials
------------------------------------

.. raw:: latex

    Given a non-null polynomial $P \in F[X]\backslash\{0\}$, $F[X]/P$ is a $F$-vector subspace and a sub-ring of $F[X]$.
    It would be a field only if every non-null polynomials in this set is invertible.

    If $P$ is not a prime polynomial, it has non-trivial divisors $A$ and $B$, such that:
    \begin{itemize}
      \item $1 \leq \deg A < \deg P$ so $A \mod P = A$
      \item $1 \leq \deg B < \deg P$ so $B \mod P = B$
      \item $P = AB$ so $AB \mod P = 0$
    \end{itemize}
    In this situation, $A$ and $B$ are non-null polynomials of $F[X]/P$ and cannot be invertible, so $F[X]/P$ is not a field.

    If $P$ is a prime polynomial, for all $A \in F_{\deg(P) - 1}[X]\backslash\{0\}$, $\gcd(A, P) = 1$ so Bézout's identity shows the existence of an inverse of $A$ in $F[X]/P$.

    \begin{theorem}[Fields over prime polynomials]
      $F[X]/P$ is a field iff $P$ is a prime polynomial of $F[X]$.
    \end{theorem}

    When $F$ is a finite set, $F[X]/P$ is also a finite set and it contains this number of polynomials:
    \begin{eqnarray*}
      |F[X]/P| = |F|^{deg(P)}
    \end{eqnarray*}

    By using $F = \Z/p\Z$ with $p$ a prime number and $P$ a polynomial of $\Z/p\Z[X]$ of degree $d$, $\Z/p\Z[X]/P$ is a finite field of $p^d$ items.
    This is called a Galois field.

AES Galois field
~~~~~~~~~~~~~~~~

AES (Advanced Encryption Standard) uses a polynomial Galois field of 256 items, named :latex:`$GF(2^{256})$` or :latex:`$\F{256}$`, in functions ``SubBytes`` (where it performs an inversion in this field) and ``MixColumns`` (where it multiplies two polynomials of :latex:`$\F{256}[X]$ modulo $X^4+1$`).

.. raw:: latex

    As $256 = 2^8$, $\F{256}$ is built using the Galois field of 2 items ($\F{2} = \{0, 1\}$) and a polynomial of degree 8, $P_{AES} = X^8 + X^4 + X^3 + X + 1 \in \F{2}[X]$.
    The primality of $P_{AES}$ can be verified by ensuring it is not a multiple of any of the 127 polynomials of $(\F{2})_7[X]\backslash\{1\}$.

It is convenient to use :latex:`$\F{256}[X]$` because all its polynomials can be written using 8 bits, which is a common unit in computer science.
