Elliptic curve
==============

.. role:: latex(raw)
     :format: latex

Notations
---------

Elliptic curves are curves in a two-dimension space (i.e. a plane).
Let :latex:`$F$` be the field in which each coordinate lives. The space is simply :latex:`$F^2$`.
This field has commutative addition and multiplication, and can be finite but it is not required.
When representing a curve graphically, the real space (:latex:`$F^2 = \R^2$`) is used, whereas several cryptography algorithms use Galois's finite fields over a prime number (:latex:`$F = \F{p} = \Z/p\Z$`).
The only strong requirement on :latex:`$F$` is for its characteristic not to be :latex:`$2$` (i.e. :latex:`$1 + 1 \neq 0$`).


Weierstrass curves
------------------

.. raw:: latex

    \begin{definition}[Weierstrass normal form]
      An elliptic curve is a curve in a plane $F^2$ composed of a point at infinity, named $O$, and of points which coordinates $(x, y) \in F^2$ satisfy an equation written in the Weierstrass normal form, with $a, b \in F$:
      \begin{equation*}
        y^2 = x^3 + ax + b
      \end{equation*}
    \end{definition}

    \begin{definition}[Non-singular curve]
      A curve in Weierstrass normal form is non-singular if its discriminant is not zero. The discriminant is:
      \begin{equation*}
        \Delta = -16(4a^3 + 27b^2)
      \end{equation*}
    \end{definition}

    The discriminant is used to compute roots of polynomial $X^3 + aX + b$.
    
    \begin{theorem}
      The curve is non-singular if and only if the polynomial $X^3 + aX + b$ does not have a double-root.
    \end{theorem}
    Proof: let's suppose that the polynomial $P = X^3 + aX + b$ has a double root $r$.
    This means that $(X - r)^2$ divides it.
    The quotient of the Euclidean division between $P$ and $(X - r)^2$ is a polynomial $Q$ of degree 1.
    Let $q = -Q(0)$
    It can be easily shown that $Q = X - q$, so:
    \begin{eqnarray*}
      P &=& (X - r)^2(X - q) \\
      X^3 + aX + b &=& X^3 - (q + 2r)X^2 + (2rq + r^2)X - r^2q
    \end{eqnarray*}
    Therefore:
    \begin{eqnarray*}
      0 &=& q + 2r \\
      a &=& 2rq + r^2 \\
      b &=& -r^2q
    \end{eqnarray*}
    This leads to:
    \begin{eqnarray*}
      q &=& -2r \\
      a &=& -3r^2 \\
      b &=& 2r^3
    \end{eqnarray*}
    Therefore:
    \begin{eqnarray*}
      4a^3 + 27b^2 = -108r^6 + 108r^6 = 0
    \end{eqnarray*}

    The other way ($\Delta = 0 \Rightarrow \text{double-root}$) can be obtained with more work.

    QED.

    \begin{definition}[Opposite point]
      With $A(x_A, y_A)$ a point of an elliptic curve, the point $(x_A, -y_A)$ also satisfy the curve equation.
      This point is called the opposite of $A$ and is written $-A$.
    \end{definition}

    \begin{definition}[Group law]
      With $A$ and $B$ two points of an elliptic curve, the line $(AB)$ (which is the tangent line if $A = B$) either crosses the curve in a third point, $C$, or not.
      If it crosses, $A + B$ is defined to $-C$. Overwise, $A + B = O$.
      This definition is extended to the point at infinity with $A + O = A = O + A$ and $O + O = O$.
    \end{definition}

    \begin{theorem}[Group law of points with different abscissa]
      With $A$ and $B$ two points of an elliptic curve with $x_A \neq x_B$.
      Let $l$ be the slope of the line $(AB): y = y_A + l (x - x_A)$.
      The sum $A + B$ is a point $S$ which coordinates are:
      \begin{eqnarray*}
        l &=& \frac{y_B - y_A}{x_B - x_A} \\
        x_S &=& l^2 - x_A - x_B \\
        y_S &=& -y_A - l (x_S - x_A)
      \end{eqnarray*}
    \end{theorem}
    Proof: the formula to compute $l$ is the definition of the slope of a line in a plane.
    The three points $A$, $B$ and $-S$ all satisfy two equations (the line $(AB)$ and the curve):
    \begin{eqnarray*}
      Y &=& y_A + l (X - x_A) \\
      Y^2 &=& X^3 + aX + b
    \end{eqnarray*}
    These equations combine together to:
    \begin{eqnarray*}
      (y_A + l (X - x_A))^2 &=& X^3 + aX + b
    \end{eqnarray*}
    This leads to a polynomial of degree 3 which roots are $x_A$, $x_B$ and $x_{-S} = x_S$:
    \begin{eqnarray*}
      Q &=& (X^3 + aX + b) - (y_A + l(X - x_A))^2 \\
      &=& X^3 + aX + b - y_A^2 - 2ly_A(X - x_A) - l^2(X - x_A)^2 \\
      &=& X^3 + aX + b - (x_A^3 + ax_A + b) - 2ly_A(X - x_A) - l^2(X - x_A)^2 \\
      &=& (X - x_A)(X^2 + x_AX + x_A^2) + a(X - x_A) - 2ly_A(X - x_A) - l^2(X - x_A)^2 \\
      &=& (X - x_A)(X^2 + x_AX + x_A^2 + a - 2ly_A - l^2(X - x_A)) \\
      &=& (X - x_A)(X^2 + x_AX + x_A^2 + a - 2ly_A - l^2(X - x_B) - l^2(x_B - x_A)) \\
      &=& (X - x_A)(X^2 - l^2(X - x_B) + x_AX + x_A^2 + a - 2ly_A - l(y_B - y_A))
    \end{eqnarray*}
    With
    \begin{eqnarray*}
      2ly_A + l(y_B - y_A) &=& l(y_B + y_A) \\
      &=& \frac{y_B - y_A}{x_B - x_A}(y_B + y_A) \\
      &=& \frac{1}{x_B - x_A}(y_B^2 - y_A^2) \\
      &=& \frac{1}{x_B - x_A}(x_B^3 + ax_B + b - x_A^3 - ax_A - b) \\
      &=& \frac{1}{x_B - x_A}(x_B - x_A)(x_B^2 + x_Ax_B + x_A^2 + a) \\
      &=& x_B^2 + x_Ax_B + x_A^2 + a
    \end{eqnarray*}
    Therefore
    \begin{eqnarray*}
      Q &=& (X - x_A)(X^2 - l^2(X - x_B) + x_AX + x_A^2 + a - x_B^2 - x_Ax_B - x_A^2 - a) \\
      &=& (X - x_A)(X^2 - x_B^2 - l^2(X - x_B) + x_A(X - x_B)) \\
      &=& (X - x_A)(X - x_B)(X + x_B - l^2 + x_A) \\
      Q &=& (X - x_A)(X - x_B)(X - (l^2 - x_B - x_A))
    \end{eqnarray*}
    $Q$ has three roots and the third one is $x_{-S}$ by definition, which leads to the expressions.

    QED.

    When $A = B$ and $y_A \neq 0$, the slope of the tangent of the elliptic curve at $A$ is:
    \begin{eqnarray*}
      l = \frac{dy}{dx} = \frac{3x_A^2 + a}{2y_A}
    \end{eqnarray*}
    Then, the same proof leads to $Q = (X - x_A)^2(X - (l^2 - 2x_A))$ so $x_S = l^2 - 2x_A$.
    \begin{theorem}[Group law of points with same abscissa]
      With $A$ and $B$ two points of an elliptic curve with $x_A = x_B$.
      If $y_A = y_B \neq 0$, $A = B$ and with $l$ the slope of the tangent at this point,
      The sum $A + A$ is a point $S$ which coordinates are:
      \begin{eqnarray*}
        l &=& \frac{3x_A^2 + a}{2y_A} \\
        x_S &=& l^2 - 2x_A \\
        y_S &=& -y_A - l (x_S - x_A)
      \end{eqnarray*}
      Otherwise, as $y_A^2 = y_B^2$, $y_B = -y_A$ so $B = -A$ and $A + B = O$.
    \end{theorem}

    By construction, it is easy to prove that this new law $+$ is commutative.
    Using the previous theorems, it is possible to prove it to be associative.
    Moreover $O$ is a neutral item for this law and every point has an inverse (its opposite).
    Therefore:
    \begin{theorem}[Group law of elliptic curve]
      The law $+$ which has been defined is a group law for the elliptic curve.
    \end{theorem}

Montgomery curves
-----------------

.. raw:: latex

    \begin{definition}[Montgomery form]
      An Montgomery curve is a curve in a plane $F^2$ composed of a point at infinity, named $O$, and of points which coordinates $(x, y) \in F^2$ satisfy an equation written in the Montgomery form, with $a, b \in F$:
      \begin{displaymath}
        by^2 = x^3 + ax^2 + x
      \end{displaymath}
      \begin{displaymath}
        b(a^2 - 4) \ne 0 \text{ (i.e. } b \neq 0 \land a \neq 2 \land a \neq -2 \text{)}
      \end{displaymath}
    \end{definition}

    It is possible to define a group law on such a curve, like Weierstrass curves.
    When $A$ and $B$ are such that $x_A \neq x_B$, the coordinates of $S = A + B$ are defined by:
    \begin{eqnarray*}
      l &=& \frac{y_B - y_A}{x_B - x_A} \\
      x_S &=& bl^2 - x_A - x_B - a \\
      y_S &=& - y_A - l (x_S - x_A)
    \end{eqnarray*}
    Here, $x_S$ can be reduced when $x_A \neq 0$ and $x_B \neq 0$:
    \begin{eqnarray*}
      x_S &=& bl^2 - x_A - x_B - a \\
      &=& b \frac{(y_B - y_A)^2}{(x_B - x_A)^2} - (x_A + x_B) - a \\
      &=& \frac{1}{(x_B - x_A)^2}(by_B^2 - 2by_Ay_B + by_A^2 - (x_B - x_A)(x_B^2 - x_A^2) - a(x_B - x_A)^2) \\
      &=& \frac{1}{(x_B - x_A)^2}(by_B^2 - 2by_Ay_B + by_A^2 - x_B^3 + x_Ax_B^2 + x_A^2x_B - x_A^3 - ax_B^2 + 2ax_Ax_B - ax_A^2) \\
      &=& \frac{1}{(x_B - x_A)^2}(x_B - 2by_Ay_B + x_A + x_Ax_B^2 + x_A^2x_B + 2ax_Ax_B) \\
      &=& \frac{1}{(x_B - x_A)^2}(x_B(1 + x_A^2 + ax_A) + x_A(1 + x_B^2 + ax_B) - 2by_Ay_B) \\
      &=& \frac{1}{x_Ax_B(x_B - x_A)^2}(x_B^2(x_A + x_A^3 + ax_A^2) + x_A^2(x_B + x_B^3 + ax_B^2) - 2bx_Ax_By_Ay_B) \\
      &=& \frac{1}{x_Ax_B(x_B - x_A)^2}(bx_B^2y_A^2 + bx_A^2y_B^2 - 2bx_Ax_By_Ay_B) \\
      x_S &=& \frac{b(x_By_A - x_Ay_B)^2}{x_Ax_B(x_B - x_A)^2}
    \end{eqnarray*}

    In order to find an equivalent Weierstrass curve, let's divide the curve equation by $b^3$:
    \begin{eqnarray*}
      by^2 &=& x^3 + ax^2 + x \\
      \left(\frac{y}{b}\right)^2 &=& \left(\frac{x}{b}\right)^3 + \frac{a}{b}\left(\frac{x}{b}\right)^2 + \frac{1}{b^2}\frac{x}{b} \\
      &=& \left(\frac{x}{b} + \frac{a}{3b}\right)^3 - 3\left(\frac{a}{3b}\right)^2\frac{x}{b} - \left(\frac{a}{3b}\right)^3 + \frac{1}{b^2}\frac{x}{b} \\
      &=& \left(\frac{x}{b} + \frac{a}{3b}\right)^3 + \left(-\frac{a^2}{3b^2} + \frac{1}{b^2}\right)\frac{x}{b} - \left(\frac{a}{3b}\right)^3 \\
      &=& \left(\frac{x}{b} + \frac{a}{3b}\right)^3 + \frac{3 - a^2}{3b^2}\left(\frac{x}{b} + \frac{a}{3b}\right) - \frac{3 - a^2}{3b^2}\frac{a}{3b} - \frac{a^3}{27b^3} \\
      \left(\frac{y}{b}\right)^2 &=& \left(\frac{x}{b} + \frac{a}{3b}\right)^3 + \frac{3 - a^2}{3b^2}\left(\frac{x}{b} + \frac{a}{3b}\right) + \frac{2a^3 - 9a}{27b^3} \\
    \end{eqnarray*}
    Therefore it is possible to define a mapping to a Weierstrass curve:
    \begin{eqnarray*}
      X &=& \frac{x}{b} + \frac{a}{3b} \\
      Y &=& \frac{y}{b} \\
      A &=& \frac{3 - a^2}{3b^2} \\
      B &=& \frac{2a^3 - 9a}{27b^3} \\
      Y^2 &=& X^3 + AX + B
    \end{eqnarray*}
    Its discriminant is:
    \begin{eqnarray*}
      4A^3 + 27B^2 &=& 4 \left(\frac{3 - a^2}{3b^2}\right)^3 + 27\left(\frac{2a^3 - 9a}{27b^3}\right)^2 \\
      &=& \frac{4(27 - 27a^2 + 9a^4 - a^6)}{27b^6} + \frac{4a^6 - 36a^4 + 81a^2}{27b^6} \\
      &=& \frac{4 \times 27(1 - a^2) + 3 \times 27 a^2}{27b^6} \\
      &=& \frac{4 - a^2}{b^6} \\
      4A^3 + 27B^2 &=& \frac{(2 - a)(2 + a)}{b^6} \neq 0
    \end{eqnarray*}
    As the transformation $(x, y) \mapsto (X, Y)$ is affine, the alignment of points is kept accross it, which is why the group law shares the same definition between Montgomery and Weierstrass curves.

    One specific feature of a Weierstrass curve is that the origin $(0, 0)$ always belong to the curve and has itself as opposite. This also means that adding the origin to itself leads to the point at infinity (like $(-1)^2 = 1$ leads to the neutral item of the multiplication).

    This also shows that not every elliptic curve can have a Weierstrass form, as $X^3 + AX + B$ needs to have a root (which would lead to the point mapping to the origin). Mathematically, more conditions need to be met in order to compute $(a, b)$ from $(A, B)$.
