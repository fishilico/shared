Modular arithmetic
==================

.. role:: latex(raw)
     :format: latex

Definitions
-----------

Operations happen in the set of integers, :latex:`\Z`.
The usual addition (+) and multiplation (. or :latex:`$\times$`) are well defined in this set (for more details, cf. Peano axioms).

.. raw:: latex

    \begin{theorem}[Euclidean division]
      \begin{equation}
        \forall a \in \Z, \forall b \in \Zs, \exists! (q, r) \in \Z^2, \\
        \left\{
          \begin{array}{c}
            0 \leq r < |b| \\
            a = bq + r
          \end{array}
        \right.
      \end{equation}
      $q$ is the quotient of the division of $a$ by $b$ and $r$ the remainder.
    \end{theorem}

This allows defining the modulo operation as the remainder of the Euclidean division of two integers:

.. raw:: latex

    \begin{equation}
        a \mod b := r
    \end{equation}

For any :latex:`$b \in \Zs$`, it is therefore possible to define the modulo relationship, :latex:`$\mathcal{R}_{b}$`:

.. raw:: latex

    \begin{equation}
      \forall (x, y) \in \Z^2, x \mathcal{R}_{b} y \iff (x - y) \mod b = 0
    \end{equation}

This binary relation is an equivalence relation, as it is:

* reflexive (:latex:`$x \mathcal{R}_{b} x$`),
* symmetric (:latex:`$x \mathcal{R}_{b} y \iff y \mathcal{R}_{b} x$`),
* transitive (:latex:`$x \mathcal{R}_{b} y \land y \mathcal{R}_{b} z \Rightarrow x \mathcal{R}_{b} z$`).

This relation is usually written using a congruence syntax:

.. raw:: latex

    \begin{equation}
      x \mathcal{R}_{b} y \iff x \equiv y [b]
    \end{equation}

Like any equivalence relation, :latex:`$\mathcal{R}_{b}$` has equivalence classes.
Each equivalence class holds a unique integer :latex:`$r \in \llbracket 0, |b|\llbracket$` (because of the Euclidean division theorem).
This integer is the canonical representative of its class.

The equivalence class which contains :latex:`$0$` is written :latex:`$\bar{0}$`:

.. raw:: latex

    \begin{equation}
      \forall x \in \Z, x \in \bar{0} \iff x \mod b = 0
    \end{equation}

So this is the set of the multiples of :latex:`$b$`.
This set is usually written :latex:`$b\Z$`.

In algebra, the set of the equivalence classes of a relation is written as a division (:latex:`$\Z/\mathcal{R}_b$`).
When the function which maps items to their equivalence class is a morphism, this set can also be written using the kernel of the morphism (i.e. the items which maps to the neutral element of the set of equivalent classes).
Here, the addition maps naturally to the set of equivalence classes, and the said kernel is :latex:`$b\Z$`.
This is why :latex:`$\Z/\mathcal{R}_b$` is often written as :latex:`$\Z/b\Z$`.


Chinese remainder theorem
-------------------------

.. raw:: latex

    \begin{theorem}[Chinese remainder theorem]
      Let $(n_1, n_2..., n_k) \in \Ns^k$ be $k$ pairwise coprime numbers (i.e. $i \ne j \Rightarrow \gcd(n_i, n_j) = 1$) and $N$ the product of these numbers.
      Let $(\bar{a_1}..., \bar{a_k}) \in \Z/n_1\Z \times ... \times \Z/n_k\Z$.
      There is only one $x \in \llbracket 0, N - 1\rrbracket$ such that:
      \begin{equation}
        \forall i \in \llbracket 1, k\rrbracket, x \equiv a_i [n_i]
      \end{equation}
    \end{theorem}

    Proof of uniqueness: if $x$ and $y$ verify the equation, $(x - y)$ is a multiple of every $n_i$.
    As these numbers are pairwise coprime, $(x-y)$ is a multiple of their product, $N$, so $x = y$.

    Proof of existence:

    As $n_1$ and $n_2$ are coprime, Bezout identity (and the Extended Euclidean algorithm) gives two integers $u_1$ and $u_2$ such that:
    \begin{equation}
      u_1 n_1 + u_2 n_2 = 1
    \end{equation}

    Let $x_{12} = a_1 u_2 n_2 + a_2 u_1 n_1$.
    \begin{eqnarray}
      x_{12} = a_1 (1 - u_1 n_1) + a_2 u_1 n_1 \equiv a_1 [n_1] \\
      x_{12} = a_1 u_2 n_2 + a_2 (1 - u_2 n_2) \equiv a_2 [n_2]
    \end{eqnarray}

    If $k = 2$, this ends the proof. Otherwise, it is possible to replace $(n_1, a_1)$ and $(n_2, a_2)$ with $(n_1 n_2, x_{12})$, decrease $k$ by 1 and iterate until $k$ equals 2.

    \begin{theorem}[Mapping of the Chinese remainder theorem]
      \label{theorem-mapping-of-chinese-remainder}
      Let $(n_1, n_2..., n_k) \in \Ns^k$ be $k$ pairwise coprime numbers and $N$ the product of these numbers.
      The following function exists and is an isomorphism for the addition and the multiplication:
      \begin{equation}
        \begin{array}{rcl}
          \Z/N\Z &\rightarrow& \Z/n_1\Z \times \Z/n_2\Z \times ... \times \Z/n_k\Z \\
          \bar{x} &\mapsto& \left(\overline{x \mod n_1}, \overline{x \mod n_2}..., \overline{x \mod n_k}\right)
        \end{array}
      \end{equation}
    \end{theorem}


Modular inverse
---------------

Let :latex:`$n \in \N$`.
:latex:`$x \in \Z/n\Z$` is inversible if there exists :latex:`$y \in \Z/n\Z$` such that :latex:`$xy = \bar{1}$`.
As the multiplication is commutative, this implies that :latex:`$yx = \bar{1}$` too.
The set of inversible items of :latex:`$\Z/n\Z$` is written :latex:`$(\Z/n\Z)^\times$`.

This :latex:`$y$` is unique. Indeed, if there exists :latex:`$y_1$` and :latex:`$y_2$` with this property,

.. raw:: latex

    \begin{equation}
      y_1 = y_1 . 1 = y_1 x y_2 = 1 . y_2 = y_2
    \end{equation}

This :latex:`$y$` is called the inverse of :latex:`$x$` and is written :latex:`$x^{-1}$`.

When talking about integers instead of equivalence classes, the definitions become:

* :latex:`$x \in \Z$` is inversible modulo :latex:`$n$` if there exists :latex:`$y \in \Z$` such that :latex:`$xy \equiv 1 [n]$`.
* The inverse of such :latex:`$x$` modulo :latex:`$n$` is the integer :latex:`$y \in \llbracket 0, n \llbracket$` such that :latex:`$xy \equiv 1 [n]$`.
* The set of integers inversible modulo :latex:`$n$` is also written :latex:`$(\Z/n\Z)^\times$`, in a kind of langage abuse.

When :latex:`$x \in \Z$` is inversible modulo :latex:`$n$`:

.. raw:: latex

    \begin{eqnarray}
      \exists (y, q) \in \Z^2, xy = qn + 1 \\
      \exists (u, v) \in \Z^2, ux + vn = 1
    \end{eqnarray}

This last equation can be used to show that there is no common divisor except 1 between :latex:`$x$` and :latex:`$n$` (this is Bezout identity).
Moreover, for any :latex:`$x \in \Z$` the Extended Euclidean algorithm builds two integers :latex:`$u$` and :latex:`$v$` such that:

.. raw:: latex

    \begin{equation}
      ux + vn = \gcd(x, n)
    \end{equation}

If :latex:`$x$` and :latex:`$n$` share no divisor except 1, their greatest common divisor is 1, which leads to:

.. raw:: latex

    \begin{eqnarray}
      ux + vn = 1 \\
      ux \equiv 1 [n]
    \end{eqnarray}

This gives a way to compute the inverse of :latex:`$x$` modulo :latex:`$n$`, and leads to the following theorem.

.. raw:: latex

    \begin{theorem}[Modular inverse]
      \label{theorem-modular-inverse}
      \begin{equation}
        \forall n \in \N,
        \forall x \in \Z,
        x \in (\Z/n\Z)^\times \iff \gcd(x, n) = 1
      \end{equation}
    \end{theorem}

Euler totient function
~~~~~~~~~~~~~~~~~~~~~~

.. raw:: latex

    \begin{definition}[Euler totient function]
      For $n \in \Ns$, the Euler totient function of $n$, $\phi(n)$, is the number of integers in $\llbracket 1, n \llbracket$ which are relatively prime to $n$:
      \begin{equation}
        \begin{array}{rcl}
          \phi : \Ns &\rightarrow& \Ns \\
          n &\mapsto& \left|\left\{x \in \llbracket 1, n \llbracket, \gcd(x, n) = 1 \right\}\right|
        \end{array}
      \end{equation}
    \end{definition}

    Using theorem \ref{theorem-modular-inverse}, it is straightforward to link this function with the set of inverses modulo $n$.

    \begin{theorem}[Alternative definition of Euler totient function]
      \begin{equation}
        \forall n \in \Ns, \phi(n) = \left| (\Z/n\Z)^\times \right|
      \end{equation}
    \end{theorem}

    Here are some properties of this function:

    \begin{equation}
      \phi(1) = 1
    \end{equation}

    If $p$ is a prime number, every integer between 1 and $p-1$ is relatively prime to $p$, so:
    \begin{equation}
      \forall p \in \Primes, \phi(p) = p - 1
    \end{equation}

    Moreover for $k \geq 2$, if $x \in \Ns$ is not relatively prime to $p^k$, $\gcd(x, p^k) \neq 1$ and a divisor of $p^k$ divides $x$.
    As every divisor of $p^k$ is a multiple of $p$, $x$ is also a multiple.
    Reciprocally every multiple of $p$ cannot be relatively prime to $p^k$.
    So the number of integers between 1 and $p^k - 1$ which are relatively prime to $p^k$ is:
    \begin{equation}
      \forall p \in \Primes, \forall k \in \Ns, \phi(p^k) = p^k - p^{k-1} = p^{k-1}(p - 1) = p^k\left(1 - \frac{1}{p}\right)
    \end{equation}

    If $m$ and $n$ are relatively primes one to each other, the Chinese remainder theorem (theorem \ref{theorem-mapping-of-chinese-remainder}) helps defining an isomorphism between $\Z/mn\Z$ and $\Z/m\Z \times \Z/n\Z$ relativelity to the multiplication.
    This morphism can be restricted to an isomorphism between $(\Z/mn\Z)^\times$ and $(\Z/m\Z)^\times \times (\Z/n\Z)^\times$.
    The existence of this isomorphism leads to the following proposition:
    \begin{equation}
      \forall m, n \in \Ns^2, \gcd(m, n) = 1 \Rightarrow \phi(mn) = \phi(m)\phi(n)
    \end{equation}


Galois fields other prime numbers
---------------------------------

When a set is provided with addition and multiplication operations, like :latex:`$(\Z/n\Z, +, .)$`, it is called a field when every non-zero item is inversible.

If :latex:`$n$` is a prime number, no integer between 1 and :latex:`$n - 1$` shares no divisors except 1 with :latex:`$n$`, so every equivalence class of :latex:`$\Z/n\Z$` which is not :latex:`$\bar 0 = n\Z$` is inversible.

Otherwise (if :latex:`$n$` is not a prime number), there exists :latex:`$d \in \llbracket 2, n - 1 \rrbracket$` which divides :latex:`$n$`, and this :latex:`$d$` is therefore not inversible modulo :latex:`$n$`.

.. raw:: latex

    \begin{theorem}[Finite fields $\Z/n\Z$]
      For $n \in \N$, $(\Z/n\Z, +, .)$ is a finite field if and only if $n$ is a prime number.
    \end{theorem}


Évariste Galois is a famous mathematician who gave his name to the finite fields, which are fields with a finite number of items (contrary to infinite fields like the set of real numbers).
He showed that the finite fields with a prime number of items can be mapped to :latex:`$\Z/n\Z$`, with :latex:`$n$` being this number of items.

As a prime number is usually written :latex:`$p \in \Primes$`, this leads to using :latex:`$\Z/p\Z$` to speak of the finite field with :latex:`$p$` items.
This field can also be written :latex:`\F{p}` or :latex:`GF($p$)` in the litterature.


Fermat's little theorem
-----------------------

.. raw:: latex

    \begin{theorem}[Fermat's little theorem]
      With $p$ a prime number,
      \begin{equation}
        \forall a \in \Z, a^p \equiv a [p]
      \end{equation}
    \end{theorem}

There exist several proofs of this theorem:latex:`\footnote{\url{https://en.wikipedia.org/wiki/Proofs_of_Fermat\%27s_little_theorem}}`.
Let's write down here a proof using modular arithmetic.

Proof of Fermat's little theorem using modular arithmetic
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

First, let's reduce the set of :latex:`$a$` to the positive integers.

* If :latex:`$p$` is odd, :latex:`$(-1)^p = -1$` so :latex:`$(-1)^p \equiv -1 [p]$`. Otherwise :latex:`$p$` is an even prime number, so :latex:`$p = 2$` and :latex:`$(-1)^p = 1 \equiv -1 [2]$`. The theorem is therefore true for :latex:`$a = -1$`. 
* If Fermat's little theorem is true for :latex:`$a \in \N$`, it is true of negative integers as well, because :latex:`$(-a)^p = (-1)^p a^p \equiv -1 . a = -a [p]$`
* If Fermat's little theorem is true for :latex:`$a \in \llbracket 0, p - 1 \rrbracket$`, it can be extended for :latex:`$a \in \N$` because every operation is modulo :latex:`$p$`.
* The theorem is trivially true for :latex:`$a = 0$`, because :latex:`$a^p = 0$` (:latex:`$p$` cannot be null).

Therefore if the theorem is true for :latex:`$a \in \llbracket 1, p - 1 \rrbracket$`, it will be true for :latex:`$a \in \Z$`.

With :latex:`$a \in \llbracket 1, p - 1 \rrbracket$`, let's study the sequence :latex:`$(a, 2a, 3a... (p - 1)a)$` modulo :latex:`$p$`:

.. raw:: latex

    \begin{equation}
      \forall i \in \N, u_i := i a \mod p
    \end{equation}

    As $a$ is inversible modulo $p$,

    \begin{equation}
      \forall i \in \N, u_i = 0 \iff ia = 0 \mod p \iff i = 0 \mod p \\
    \end{equation}
    \begin{equation}
      \forall i \in \llbracket 1, p - 1 \rrbracket, u_i \ne 0
    \end{equation}

    Moreover, for $(i, j) \in \N^2$ such that $1 \leq i < j \leq p - 1$,

    \begin{equation}
      u_j - u_i = ja - ia = (j - i)a \equiv u_{j-i} [p]
    \end{equation}

    If $u_j = u_i$, $u_{j-i} \equiv 0 [p]$ so $u_{j-i} = 0$ because $u_{j-i} \in \llbracket 0, p \llbracket$.
    This is incompatible with $1 \leq j - i \leq p - 1$.

    Therefore $u_j \neq u_i$.

    This shows that every item in the sequence $(u_1, u_2..., u_{p-1})$ is unique and in $\llbracket 1, p - 1 \rrbracket$.
    So the products of all the items of the sequence is equals to the product of all integers between 1 and $p - 1$:

    \begin{eqnarray}
      \prod_{i=1}^{p-1} u_i &=& \prod_{i=1}^{p-1} i \\
      \prod_{i=1}^{p-1} ((ia) \mod p) &=& \prod_{i=1}^{p-1} i \\
      \prod_{i=1}^{p-1} ((ia) \mod p) &\equiv& \prod_{i=1}^{p-1} i [p] \\
      \left(\prod_{i=1}^{p-1} i\right)\left(\prod_{i=1}^{p-1} a\right) &\equiv& \prod_{i=1}^{p-1} i [p]
    \end{eqnarray}

    As every integer from 1 to $p - 1$ is inversible,

    \begin{eqnarray}
      a^{p - 1} &\equiv& 1 [p] \\
      a^p &\equiv& a [p]
    \end{eqnarray}

Modular inverse consequence of Fermat's little theorem
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For :latex:`$p \in \Primes$`, and :latex:`$a \in (\Z/p\Z)^\times$`.
As :latex:`$a . a^{p - 2} = a^{p - 1} \equiv 1 [p]$`, the inverse of :latex:`$a$` modulo :latex:`$p$` is :latex:`$a^{p - 2} \mod p$`.

Euler's theorem
---------------

Euler's theorem is a generalisation of Fermat's little theorem.

.. raw:: latex

    \begin{theorem}[Euler's theorem]
      \begin{equation}
        \forall n \in \Ns, \forall a \in \Z, \gcd(a, n) = 1 \Rightarrow a^{\phi(n)} \equiv 1 [n]
      \end{equation}
    \end{theorem}

    This theorem can be proven using Lagrange theorem on the group $\left((\Z/n\Z)^\times, \times\right)$.

Lagrange theorem
~~~~~~~~~~~~~~~~

.. raw:: latex

    \begin{theorem}[Lagrange theorem]
      For any finite group $G$, the number of elements (i.e. the order) of every subgroup $H$ of $G$ divides the number of elements of $G$.
    \end{theorem}

    Proof of Lagrange theorem:

    Let $H$ be a subgroup of $G$.
    Let $\mathcal{R}_H$ be the relation defined by:
    \begin{eqnarray}
      \forall (x, y) \in G^2, x \mathcal{R}_H y &\iff& \exists h \in H, x = yh \\
      &\iff& y^{-1} x \in H
    \end{eqnarray}
    This defines an equivalence relation and its equivalence classes are the "cosets" of $H$.
    With $a \in G$,
    \begin{eqnarray}
      \forall x \in G, x \in \bar{a} &\iff& x \mathcal{R}_H a \\
      &\iff& \exists h \in H, x = ah \\
      &\iff& x \in aH
    \end{eqnarray}
    Hence the equivalence class of $a \in G$ is $aH$.

    With $(a, b) \in G^2$, the function $x \mapsto ba^{-1}x$ maps any element from $aH$ to $bH$, and $x \mapsto ab^{-1}x$ is its reciproqual.
    This is therefore a bijection between two finite sets (because $G$ is finite), so all equivalence classes share the same number of elements ($|aH| = |bH|$).
    The equivalence classes form a partition of $G$.
    With $[G:H]$ being the number of equivalence classes, this partition leads to:
    \begin{eqnarray}
      |G| = [G:H] |H| \\
      |H| \text{ divides } |G|
    \end{eqnarray}

QED.

Proof of Euler's theorem
~~~~~~~~~~~~~~~~~~~~~~~~

.. raw:: latex

    In order to prove Euler's theorem, let's apply it to $G = (\Z/n\Z)^\times$ and $H = {a^i, i \in \N}$ with $a \in \Z$ such that $\gcd(a, n) = 1$.
    $(H, \times)$ is a subgroup of $G$ ($H$ is the orbit of $a$) and is finite.
    Therefore there exists $(i, j) \in \N^2$ such that $i < j$ and $a^i \equiv a^j [n]$.
    As $a$ is inversible modulo $n$, $a^{j-i} \equiv 1 [n]$, with $j - i > 0$.
    This allows to define the order of $a$ in $(\Z/n\Z)^\times$:
    \begin{equation}
      \ord_n(a) := \min\left(i \in \Ns, a^i \equiv 1 [n]\right)
    \end{equation}

    Every number from $(1, a, a^2, a^3..., a^{\ord_n(a) - 1})$ is different modulo n, because if $a^i \equiv a^j [n]$ with $0 \leq i < j < \ord_n(a)$, $a^{j-i} \equiv 1 [n]$ with $j-i < \ord_n(a)$.
    Moreover $H = \{1, a, a^2, a^3..., a^{\ord_n(a) - 1}\}$ because it \emph{loops} at the order of $a$.
    Therefore:
    \begin{equation}
      |H| = \ord_n(a)
    \end{equation}
    \begin{equation}
      \ord_n(a) \text{ divides } |G| = |(\Z/n\Z)^\times| = \phi(n)
    \end{equation}
    Let $m \in \Z$ such that $\phi(n) = m\ord_n(a)$.
    \begin{equation}
      a^{\phi(n)} = a^{m\ord_n(a)} = \left(a^{\ord_n(a)}\right)^m \equiv 1^m = 1 [n]
    \end{equation}

QED.


Modular square root
-------------------

The question of finding a square root :latex:`$r$` of an integer :latex:`$x$` modulo :latex:`$n$` (i.e. such that :latex:`$r^2 \equiv x [n]$`) has a different answer than when working on real numbers.
In modular arithmetic, some numbers to not have a square root, :latex:`$-1$` may have one, etc. and the algorithm to compute one is very different from the approximation used for real numbers.

The values :latex:`$n = 1$` and :latex:`$n = 2$` are not very interesting:

* :latex:`$\Z/1Z$` contains a single element, 0, which is its own square root.
* :latex:`$\Z/2Z$` contains two elements (0 and 1), which squares are themselves. So their square roots are themselves too.

Things become more interesting with :latex:`$n \geq 3$`.

Euler's criterion
~~~~~~~~~~~~~~~~~

.. raw:: latex

    A number is a quadratic residue if it is the square of an integer.

    \begin{theorem}[Euler's criterion]
      With $p$ an odd prime number and $a \in \Z$ coprime to $p$ (i.e. $a \mod p \neq 0$),
      \begin{equation}
        a^\frac{p-1}{2} \equiv \left\{\begin{array}{rl}
          1 [p] & \text{if $a$ is a quadratic residue modulo $p$} \\
          -1 [p] & \text{if $a$ is not a quadratic residue modulo $p$}
        \end{array}\right.
      \end{equation}
    \end{theorem}

    Here is a proof.

    First, according to Fermat's little theorem,
    \begin{eqnarray}
      a^{p-1} &\equiv& 1 [p] \\
      \left(a^\frac{p-1}{2}\right)^2 &\equiv& 1 [p]
    \end{eqnarray}

    Therefore $a^\frac{p-1}{2}$ is a root of $X^2 - 1 = (X - 1)(X + 1)$ in the finitie field $\F{p}$, which leads to $a^\frac{p-1}{2} \equiv \pm 1 [p]$.
    (This comes from the fact that $xy = 0 \Rightarrow x = 0 \lor y = 0$ in a field because every non-null element is inversible.)

    By grouping the numbers in $\llbracket 1, p - 1 \rrbracket$ by pairs $(x, p-x)$ with $x$ being odd, each pair matches a unique quadratic residue (because $(p-x)^2 \equiv x^2 [p]$) and every matched residue is distinct (because $X^2 - x^2$ has at most two roots).
    Therefore there are at least $\frac{p-1}{2}$ quadratic residues.

    If $a$ is a quadratic residue modulo $p$, let $x$ be a square root of $a$.
    Then $x \mod p$ cannot be zero so Fermat's little theorem and the fact that $p$ is odd give:
    \begin{equation}
      1 \equiv x^{p - 1} \equiv x^{2\frac{p-1}{2}} = \left(x^2\right)^{\frac{p-1}{2}} \equiv a^{\frac{p-1}{2}} [p]
    \end{equation}

    Therefore the polynomial $X^\frac{p-1}{2} - 1$ has at least $\frac{p-1}{2}$ roots (the quadratic residues).
    As it cannot have more roots (according to Lagrange theorem on polynomials), the quadratic nonresidues are not root of this polynomial.
    If $a$ is not a quadratic-residue, $a^\frac{p-1}{2} \equiv \pm 1 [p]$ and it is not a root of $X^\frac{p-1}{2} - 1$ so $a^\frac{p-1}{2} \equiv -1 [p]$.

QED.

Legendre symbol
~~~~~~~~~~~~~~~

.. raw:: latex

    \begin{definition}[Legendre symbol]
      For $p \in \Primes$, $p \leq 3$ and for $a \in \Z$, the Legendre symbol of $a$ and $p$ is:
      \begin{equation}
        \left(\frac{a}{p}\right) = \left\{\begin{array}{rl}
          1 & \text{if $a$ is a quadratic residue modulo $p$ and $a \not\equiv 0 [p]$} \\
          -1 & \text{if $a$ is not a quadratic residue modulo $p$} \\
          0 & \text{if $p$ divides $a$}
        \end{array}\right.
      \end{equation}
    \end{definition}

    Using Euler's criterion it is possible to define a constructive definition of the Legendre symbol.

    \begin{theorem}[Legendre symbol with Euler's criterion]
      \label{theorem-legendre-symbol-euler-criterion}
      With $p$ an odd prime number and $a \in \Z$,
      \begin{equation}
        \left(\frac{a}{p}\right) \equiv a^\frac{p-1}{2} [p]
      \end{equation}
    \end{theorem}

    This definition leads to the multiplicative property of the Legendre symbol.
    \begin{equation}
      \forall (a, b) \in \Z^2, \left(\frac{ab}{p}\right) = \left(\frac{a}{p}\right)\left(\frac{b}{p}\right)
    \end{equation}

Gauss's lemma
~~~~~~~~~~~~~

.. raw:: latex

    \begin{theorem}[Gauss's lemma]
      With $p$ an odd prime number and $a \in \Z$ coprime to $p$,
      let $S = \left\{a, 2a..., \frac{p-1}{2}a\right\}$.
      Each integer of $S$ can be reduced modulo $p$ in interval $\left\llbracket-\frac{p-1}{2},\frac{p-1}{2}\right\rrbracket$.
      Let $S'$ be the resulting set on reduced integers and $n$ the number of negative numbers in $S'$.
      \begin{equation}
        \left(\frac{a}{p}\right) = (-1)^n
      \end{equation}
    \end{theorem}

    Proof:
    \begin{equation}
      \left\llbracket-\frac{p-1}{2},\frac{p-1}{2}\right\rrbracket = \left\{0, -1, 1, -2, 2..., -\frac{p-1}{2}, \frac{p-1}{2}\right\}
    \end{equation}

    If $0 \in S'$, there is $ka \in S$ such that $ka \equiv 0 [p]$.
    As $\gcd(a, p) = 1$, $k \equiv 0 [p]$, which is impossible.

    If there exists $x \in S'$ such that $-x \in S'$, there exist $k, l$ such that
    \begin{eqnarray}
      1 \le k \le \frac{p-1}{2} \\
      1 \le l \le \frac{p-1}{2} \\
      ka \equiv x [p] \\
      la \equiv -x [p]
    \end{eqnarray}
    Therefore
    \begin{eqnarray}
      2 \le k + l \le p - 1 \\
      (k + l)a \equiv 0 [p]
    \end{eqnarray}
    This is impossible.

    Similarly, every element in $S'$ is distinct.
    As $S'$ contains $\frac{p-1}{2}$ elements, it can be rewritten as $\left\{\epsilon_1.1, \epsilon_2.2..., \epsilon_{\frac{p-1}{2}}\frac{p-1}{2}\right\}$, with $\epsilon_k \in \{-1, 1\}$.

    The number of negative numbers in $S'$ is the number of negative $\epsilon_k$.
    Therefore
    \begin{equation}
      (-1)^n = \prod_{k=1}^{\frac{p-1}{2}}\epsilon_k
    \end{equation}

    The product of items of $S$ modulo $p$ can be computed using two ways:
    \begin{eqnarray}
      \prod_{s \in S} s \equiv \prod_{s \in S'}s [p] \\
      \frac{p-1}{2}! a^\frac{p-1}{2} \equiv \frac{p-1}{2}!\prod_{k=1}^{\frac{p-1}{2}}\epsilon_k [p] \\
      \left(\frac{a}{p}\right) = (-1)^n
    \end{eqnarray}

QED.

Quadratic reciprocity
~~~~~~~~~~~~~~~~~~~~~

.. raw:: latex

    \begin{theorem}[Law of quadratic reciprocity]
      With $p$ and $q$ two distinct odd prime numbers
      \begin{equation}
        \left(\frac{p}{q}\right)\left(\frac{q}{p}\right) = (-1)^{\frac{p-1}{2}\frac{q-1}{2}}
      \end{equation}
    \end{theorem}

    Proof:
    Let's study the isomorphism from the Chinese Remainder Theorem (theorem \ref{theorem-mapping-of-chinese-remainder}):
    \begin{equation}
      \begin{array}{rccl}
        f :& (\Z/pq\Z)^\times &\rightarrow& (\Z/p\Z)^\times \times (\Z/q\Z)^\times \\
        &\bar{x} &\mapsto& \left(\overline{x \mod p}, \overline{x \mod q}\right)
      \end{array}
    \end{equation}

    Let split each set into halves according to sign (when mapping items of $\Z/n\Z$ in $\left\llbracket -\frac{n-1}{2},\frac{n-1}{2}\right\rrbracket$).

    Let $U = \{f(1), f(-1)\} = \{(1, 1), (-1, -1)\} \in (\Z/p\Z)^\times \times (\Z/q\Z)^\times$.
    $(U, .)$ is a subgroup of $(\Z/p\Z)^\times \times (\Z/q\Z)^\times$.
    The product of elements of $E = (\Z/p\Z)^\times \times (\Z/q\Z)^\times /U$ can be computed in several ways.

    First, $E = \left\{\left(\overline{x \mod p}, \overline{x \mod q}\right) U, 1 \le x \le \frac{pq - 1}{2} \land \gcd(x, pq) = 1\right\}$.
    The $x$ which appear can be enumerated by skipping the multiples of $p$ and $q$ until $\frac{pq - 1}{2}$.
    \begin{eqnarray}
      \prod_{x=1,\gcd(x, pq) = 1}^{\frac{pq - 1}{2}} x &\equiv& \frac{\frac{pq - 1}{2}!}{\left(p . 2p ... \frac{q-1}{2}p\right)\left(q . 2q ... \frac{p-1}{2}q\right)} [p] \\
      &\equiv& \frac{\left(1.2..(p-1)\right)\left((p+1)...(2p-1)\right)...\left(...(\frac{q-1}{2}p+\frac{p-1}{2})\right)}{q . 2q ... \frac{p-1}{2}q} [p] \\
      &\equiv& \frac{\left(1.2..(p-1)\right)\left(1...(p-1)\right)...\left(1...(p-1)\right)\left(1...\frac{p-1}{2}\right)}{\frac{p-1}{2}!q^\frac{p-1}{2}} [p] \\
      &\equiv& \frac{(p-1)!^\frac{q-1}{2}}{q^\frac{p-1}{2}} [p]
    \end{eqnarray}
    As $q^\frac{p-1}{2} \equiv \left(\frac{q}{p}\right) [p]$, and its value is $\pm 1$,
    \begin{equation}
      \prod_{x=1,\gcd(x, pq) = 1}^{\frac{pq - 1}{2}} x \equiv (p-1)!^\frac{q-1}{2}\left(\frac{q}{p}\right) [p]
    \end{equation}
    Therefore,
    \begin{equation}
      \prod_{e \in E} e = \left((p-1)!^\frac{q-1}{2}\left(\frac{q}{p}\right), (q-1)!^\frac{p-1}{2}\left(\frac{p}{q}\right)\right)U
    \end{equation}

    Second, $E$ can also be splitted as $(\Z/p\Z)^\times \times \left\llbracket 1, \frac{q-1}{2}\right\rrbracket$:
    \begin{equation}
      \prod_{e \in E} e = \left((p-1)!^\frac{q-1}{2}, \left(\frac{q-1}{2}\right)!^{p-1}\right) U
    \end{equation}

    The last factor can be rewritten:
    \begin{eqnarray}
      \left(\frac{q-1}{2}\right)! &\equiv& \prod_{x=1}^{\frac{q-1}{2}} x [q] \\
      &\equiv& \prod_{x=1}^{\frac{q-1}{2}} \left(-(q - x)\right) [q] \\
      &\equiv& (-1)^\frac{q-1}{2} \prod_{x=\frac{q+1}{2}}^{q-1} x [q] \\
      \left(\frac{q-1}{2}\right)!\left(\frac{q-1}{2}\right)! &\equiv& (-1)^\frac{q-1}{2} \prod_{x=1}^{q-1} x [q] \\
      \left(\frac{q-1}{2}\right)!^2 &\equiv& (-1)^\frac{q-1}{2} (q-1)! [q] \\
      \left(\frac{q-1}{2}\right)!^{p-1} &\equiv& (-1)^{\frac{p-1}{2}\frac{q-1}{2}} (q-1)!^\frac{p-1}{2} [q]
    \end{eqnarray}
    Therefore
    \begin{equation}
      \prod_{e \in E} e = \left((p-1)!^\frac{q-1}{2}, (-1)^{\frac{p-1}{2}\frac{q-1}{2}} (q-1)!^\frac{p-1}{2}\right) U
    \end{equation}

    Combining these two ways leads to:
    \begin{equation}
      \left((p-1)!^\frac{q-1}{2}\left(\frac{q}{p}\right), (q-1)!^\frac{p-1}{2}\left(\frac{p}{q}\right)\right)U = \left((p-1)!^\frac{q-1}{2}, (-1)^{\frac{p-1}{2}\frac{q-1}{2}} (q-1)!^\frac{p-1}{2}\right) U
    \end{equation}
    \begin{equation}
      \left(\frac{p}{q}\right)\left(\frac{q}{p}\right) = (-1)^{\frac{p-1}{2}\frac{q-1}{2}}
    \end{equation}

QED.

Square root of -1
~~~~~~~~~~~~~~~~~

.. raw:: latex

    Let $p$ be an odd prime.
    $-1$ is a quadratic residue modulo $p$ iff $\left(\frac{-1}{p}\right) = 1$.
    Using the definition of the Legendre symbol (theorem \ref{theorem-legendre-symbol-euler-criterion}),
    \begin{equation}
      \left(\frac{-1}{p}\right) \equiv (-1)^\frac{p-1}{2} [p]
    \end{equation}

    If $p \equiv 3 [4]$, $\frac{p-1}{2}$ is odd so $(-1)^\frac{p-1}{2} = -1$ and $-1$ is a quadratic nonresidue.
    Otherwise, $p \equiv 1 [4]$ because $p$ is odd and $-1$ is a quadratic residue.
    In such a case, the square root of $-1$ can be computed using any non-quadratic residue $x$:
    \begin{equation}
      -1 = \left(\frac{x}{p}\right) \equiv x^\frac{p-1}{2} = x^{2\frac{p-1}{4}} = (x^\frac{p-1}{4})^2 [p]
    \end{equation}

    \begin{theorem}[Square root of $-1$]
      With $p \in \Primes$,
      \begin{itemize}
        \item If $p \equiv 0 [2]$, $p = 2$ and $-1 \equiv 1 [p]$ is a quadratic residue with one square root, itself.
        \item If $p \equiv 3 [4]$, $-1$ is a quadratic nonresidue modulo $p$.
        \item If $p \equiv 1 [4]$, $-1$ is a quadratic residue and its square roots are $\pm x^\frac{p-1}{4} \mod p$, with $x$ being any quadratic nonresidue modulo $p$.
      \end{itemize}
    \end{theorem}

Square root of 2
~~~~~~~~~~~~~~~~

.. raw:: latex

    Let $p$ be an odd prime.
    2 is a quadratic residue modulo $p$ iff $\left(\frac{2}{p}\right) = 1$.

    Let's compute the Legendre symbol using Gauss's lemma.
    Let $S = {2, 4, 6..., p-1}$ and $S'$ the set of these integers reduced modulo $p$ in $\left\llbracket-\frac{p-1}{2},\frac{p-1}{2}\right\rrbracket$.
    Let $n$ the number of negative integers in $S'$.
    Gauss's lemma states that:
    \begin{equation}
      \left(\frac{2}{p}\right) = (-1)^n
    \end{equation}

    \begin{eqnarray}
      n &=& \left|\left\{ s \in S', s < 0 \right\}\right| \\
      &=& \left|\left\{ k \in \llbracket 1, \frac{p-1}{2} \rrbracket, \frac{p+1}{2} \le 2k \mod p \le p - 1 \right\}\right| \\
      &=& \left|\left\llbracket \left\lceil\frac{p+1}{4}\right\rceil, \frac{p-1}{2} \right\rrbracket\right|
    \end{eqnarray}

    The value of $(-1)^n$ depends on the value of $p \mod 8$.
    Let $2r+1 = p \mod 8$ and $a$ the quotient of the division of $p$ by 8: $p = 8a + 2r + 1$.

    \begin{eqnarray}
      n &=& \left|\left\llbracket \left\lceil 2a + \frac{r+1}{2}\right\rceil, 4a + r \right\rrbracket\right| \\
      &=& 4a + r + 1 - \left\lceil 2a + \frac{r+1}{2} \right\rceil \\
      &\equiv& r + 1 - \left\lceil \frac{r+1}{2} \right\rceil [2] \\
      &\equiv& \left\{\begin{array}{l}
          0 [2] \text{ if }r \equiv 0 [4] \\
          1 [2] \text{ if }r \equiv 1 [4] \\
          1 [2] \text{ if }r \equiv 2 [4] \\
          0 [2] \text{ if }r \equiv 3 [4] \\
        \end{array}\right.
    \end{eqnarray}

    Therefore:
    \begin{equation}
      \left(\frac{2}{p}\right) = (-1)^n = \left\{\begin{array}{rl}
          1 &\text{ if }p \equiv 1 [8] \\
          -1 &\text{ if }p \equiv 3 [8] \\
          -1 &\text{ if }p \equiv 5 [8] \\
          1 &\text{ if }p \equiv 7 [8] \\
        \end{array}\right.
    \end{equation}

    \begin{theorem}[Square root of $-1$]
      With $p \in \Primes$,
      \begin{itemize}
        \item If $p \equiv 0 [2]$, $p = 2$ and $2 \equiv 0 [p]$ is a quadratic residue with one square root, itself.
        \item If $p \equiv 3 [8]$ or $p \equiv 5 [8]$, $2$ is a quadratic nonresidue modulo $p$.
        \item If $p \equiv 1 [8]$ or $p \equiv 7 [8]$, $2$ is a quadratic residue modulo $p$.
      \end{itemize}
    \end{theorem}

Square root of simple cases
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. raw:: latex

    If $p \equiv 3 [4]$,
    \begin{eqnarray}
      \forall x \in (\Z/p\Z)^\times, \left(\frac{x}{p}\right) = 1 & \iff & x^\frac{p-1}{2} \equiv 1 [p] \\
      &\iff& x^{\frac{p-1}{2} + 1} \equiv x [p] \\
      &\iff& x^{\frac{p+1}{4} . 2} \equiv x [p] \\
      &\iff& \left(x^\frac{p+1}{4}\right)^2 \equiv x [p]
    \end{eqnarray}

    If $x$ is a quadratic residue modulo $p$, $x^\frac{p+1}{4}$ is a square root of $x$.

    If $p \equiv 5 [8]$, $-1$ is a residue modulo $p$ and $2$ is not.
    Let's define a square root of $-1$:
    \begin{equation}
      i := 2^\frac{p-1}{4} \mod p
    \end{equation}
    For $x \in (\Z/p\Z)^\times$,
    \begin{eqnarray}
      \left(\frac{x}{p}\right) = 1 & \iff & x^\frac{p-1}{2} \equiv 1 [p] \\
      &\iff& \left(x^\frac{p-1}{4}\right)^2 \equiv 1 [p] \\
      &\iff& x^\frac{p-1}{4} \equiv 1 [p] \lor x^\frac{p-1}{4} \equiv -1 [p] \\
      &\iff& x^\frac{p+3}{4} \equiv x [p] \lor -x^\frac{p+3}{4} \equiv x [p] \\
      &\iff& \left(x^\frac{p+3}{8}\right)^2 \equiv x [p] \lor \left(ix^\frac{p+3}{8}\right)^2 \equiv x [p]
    \end{eqnarray}

    If $x$ is a quadratic residue modulo $p$, either $x^\frac{p+3}{8}$ or $ix^\frac{p+3}{8}$ is a square root of $x$.

    If $p \equiv 1 [8]$, a more generic algorithm needs to be applied.

Cipolla's algorithm
~~~~~~~~~~~~~~~~~~~

.. raw:: latex

    Let $p$ be an odd prime and $x$ a non-null quadratic residue modulo $p$:
    \begin{equation}
      x^\frac{p - 1}{2} \equiv 1 [p]
    \end{equation}
    The aim of Cipolla's algorithm is to compute $r \in \Z$ such that $r^2 \equiv x [p]$.

    Let's find $a \in \llbracket 1, p - 1 \rrbracket$ such that $a^2 - x$ is a quadratic non-residue modulo $p$:
    \begin{equation}
      \left(a^2 - x\right)^\frac{p - 1}{2} \equiv -1 [p]
    \end{equation}
    This can be done in a random way because there are $\frac{p-1}{2}$ such numbers.

    Let $\F{p^2} = \F{p}[X]/(X^2 - a^2 + x)$ be a set where elements are represented by $x + y\sqrt{a^2 - x}$, with $(x, y) \in (\Z/p\Z)^2$.
    $(\F{p^2}, +, .)$ is a finite field.
    Therefore if $\pm r$ are the roots of $X^2 - x$ in $\Z/p\Z$, they are also the roots (and there are only these two ones) of this polynomial in $\F{p^2}$.

    It is possible to compute in $\F{p^2}$:
    \begin{equation}
      r := \left(a + \sqrt{a^2 - x}\right)^\frac{p+1}{2}
    \end{equation}

    Let's show that $r^2 = x$ in $\F{p^2}$.

    Let $\omega = \sqrt{a^2 - x} \in \F{p^2}$.
    \begin{equation}
      \omega^{p-1} = \left(\omega^2\right)^\frac{p-1}{2} = \left(a^2 - x\right)^\frac{p - 1}{2} = -1 \text{ in $\F{p^2}$}
    \end{equation}
    \begin{eqnarray}
      r^2 &=& \left(a + \omega\right)^{\frac{p+1}{2}.2} \\
      &=& (a + \omega)^{p+1} \\
      &=& (a + \omega)(a + \omega)^p \\
      &=& (a + \omega)(a^p + \omega^p) \text{ because $p = 0$ in $\F{p^2}$} \\
      &=& (a + \omega)(a - \omega) \text{ because $a^{p-1} = 1$ and $\omega^{p-1} = -1$} \\
      &=& a^2 - \omega^2 \\
      &=& a^2 - (a^2 - x) \\
      &=& x
    \end{eqnarray}

    As $\F{p^2}$ is a field, $X^2 - x$ only has two roots in it, which are therefore $\pm r$.
    This polynomial also has roots in $\Z/p\Z$ and any root in it has to be a root in $\F{p^2}$.
    This is why $r \in \Z/p\Z$.

    To conclude, this algorithm built a square root ($r$) of $x$ modulo $p$.
