Trigonometry
============

Definitions
-----------

Given a right triangle :math:`ABC` with :math:`C` being the 90°-angle, let :math:`\theta` be the measure of the angle A.
The edges :math:`AB`, :math:`AC`, :math:`BC` are named *hypotenuse*, *adjacent* and *opposite* edges.
Let :math:`c`, :math:`b` and `a` be their respective lengths.

.. raw:: latex

    \begin{center}
    \begin{tikzpicture}
      \draw
        (0,0) coordinate (A) node[left] {$A$}
        -- node[below,midway]{$b$}
        (4,0) coordinate (C) node[right] {$C$}
        -- node[right,midway]{$a$}
        (4,3) coordinate (B) node[right] {$B$}
        -- node[above left,midway]{$c$}
        (A)
        pic[draw=black, "$\theta$", angle eccentricity=1.2, angle radius=1cm] {angle=C--A--B}
        (C) rectangle (3.7, 0.3);
    \end{tikzpicture}
    \end{center}

Thales's theorem states that the ratio of the lengths only depends on :math:`\theta`.
This allows defining the sine, the cosine and the tangent of this angle:

* :math:`\sin\theta = \frac{a}{c}`
* :math:`\cos\theta = \frac{b}{c}`
* :math:`\tan\theta = \frac{a}{b}`

This allows defining these functions when :math:`0 < \theta < \frac{\pi}{2}`.
These functions are continuous and can be extended using the limits at the bounds of their definition interval:

* :math:`\sin 0 = 0`, :math:`\cos 0 = 1`, :math:`\tan 0 = 0`
* :math:`\sin \frac{\pi}{2} = 1`, :math:`\cos \frac{\pi}{2} = 0`, :math:`\tan \frac{\pi}{2}` is not defined.

Using a circle centered on :math:`A` and of radius :math:`c = 1`, the abscissa and ordinate of :math:`C` are :math:`(\cos\theta, \sin\theta)`.
Expanding this fact on the whole circle leds to the following relatonships:

* :math:`\sin \left(\frac{\pi}{2} + \theta\right) = \cos\theta`, :math:`\sin \left(\pi + \theta\right) = -\sin\theta` and :math:`\sin \left(\pi + \theta\right) = \sin\theta`, for :math:`\theta \in \R`
* :math:`\cos\left(\frac{\pi}{2} + \theta\right) = -\sin\theta`, :math:`\cos \left(\pi + \theta\right) = -\cos\theta` and :math:`\cos \left(\pi + \theta\right) = \cos\theta`, for :math:`\theta \in \R`
* :math:`\tan\theta = \frac{\sin\theta}{\cos\theta}`, for :math:`\theta \in \R` where :math:`\cos\theta \neq 0`, so :math:`\tan(\pi + \theta) = \tan\theta`

This way, functions :math:`\sin` and :math:`\cos` are defined on :math:`\R` and function :math:`\tan` is defined on :math:`\R\backslash\left\{k\pi + \frac{\pi}{2}, k \in \Z\right\}`

Here are some straightforward formulas:

* :math:`\sin^2 \theta + \cos^2 \theta = 1` (Pythagore's theorem)
* :math:`\sin \left(\frac{\pi}{2} - \theta\right) = \cos\theta` (this is the sine of angle :math:`B`)
* :math:`\cos \left(\frac{\pi}{2} - \theta\right) = \sin\theta` (this is the cosine of angle :math:`B`)
* :math:`\sin \left(-\theta\right) = -\sin \theta` (:math:`\sin` is an odd function)
* :math:`\cos \left(-\theta\right) = \cos \theta` (:math:`\cos` is an even function)

Special values
--------------

* :math:`\sin\frac{\pi}{6} = \frac{1}{2}` and :math:`\cos\frac{\pi}{6} = \frac{\sqrt{3}}{2}` (from an equilateral triangle)
* :math:`\sin\frac{\pi}{4} = \frac{\sqrt{2}}{2}` and :math:`\cos\frac{\pi}{4} = \frac{\sqrt{2}}{2}` (from a square)
* :math:`\sin\frac{\pi}{3} = \frac{\sqrt{3}}{2}` and :math:`\cos\frac{\pi}{3} = \frac{1}{2}` (from an equilateral triangle)

Additive formulas
-----------------

For all :math:`a, b \in \R`:

* :math:`\sin(a + b) = \sin a \cos b + \cos a \sin b`
* :math:`\cos(a + b) = \cos a \cos b - \sin a \sin b`
* :math:`\sin(a - b) = \sin a \cos b - \cos a \sin b`
* :math:`\cos(a - b) = \cos a \cos b + \sin a \sin b`

Therefore:

* :math:`\sin(2a) = 2\sin a \cos b`
* :math:`\cos(2a) = \cos^2 a - \sin^2 a = 1 - 2\sin^2 a = 2\cos^2 a - 1`
* :math:`\sin a + \sin b = 2 \sin \frac{a+b}{2} \cos \frac{a-b}{2}`
* :math:`\sin a - \sin b = 2 \cos \frac{a+b}{2} \sin \frac{a-b}{2}`
* :math:`\cos a + \cos b = 2 \cos \frac{a+b}{2} \cos \frac{a-b}{2}`
* :math:`\cos a - \cos b = -2 \sin \frac{a+b}{2} \sin \frac{a-b}{2}`

And:

* :math:`1 + \cos\theta = 2\cos^2\left(\frac{\theta}{2}\right)`
* :math:`1 - \cos\theta = 2\sin^2\left(\frac{\theta}{2}\right)`
* :math:`\sin\theta = 2\sin\left(\frac{\theta}{2}\right)\cos\left(\frac{\theta}{2}\right) = 2\sin\left(\frac{\theta}{2}\right) - 4\sin\left(\frac{\theta}{2}\right)\sin^2\left(\frac{\theta}{4}\right)`

Limits
------

The most fundamental limit formula of the trigonometry functions is:

.. raw:: latex

    \begin{equation}
      \lim_{\theta \rightarrow 0}\frac{\sin \theta}{\theta} = 1
    \end{equation}

This can be proved by drawing an arc of radius 1 with angle :math:`\theta` and using some inequalities about the distances, for :math:`0 < \theta < \frac{\pi}{2}`.

.. raw:: latex

    \begin{eqnarray*}
      \sin\theta < &\theta& < \tan\theta + \left(\frac{1}{\cos\theta} - 1\right) \\
      \sin\theta < &\theta& < \frac{\sin\theta + 1 - \cos\theta}{\cos\theta} \\
      \frac{\sin\theta}{\theta} < &1& < \frac{\sin\theta + 1 - \cos\theta}{\theta\cos\theta} \\
      \frac{\sin\theta}{\theta} < 1 & \text{ and } & \cos\theta < \frac{\sin\theta}{\theta} + \frac{1 - \cos\theta}{\theta} \\
      \cos\theta - \frac{1 - \cos\theta}{\theta} &<& \frac{\sin\theta}{\theta} < 1
    \end{eqnarray*}

    With:
    \begin{eqnarray*}
      \frac{1 - \cos\theta}{\theta} &=& \frac{2}{\theta}\left(\sin \frac{\theta}{2}\right)^2 \\
      -\frac{1 - \cos\theta}{\theta} &=& - \frac{\sin \frac{\theta}{2}}{\frac{\theta}{2}}\sin \frac{\theta}{2} > -\sin \frac{\theta}{2} \\
      \cos\theta - \frac{1 - \cos\theta}{\theta} &>& \cos\theta - \sin \frac{\theta}{2}
    \end{eqnarray*}

    Therefore:
    \begin{eqnarray*}
      \cos\theta - \sin \frac{\theta}{2} < \frac{\sin\theta}{\theta} < 1
    \end{eqnarray*}
    As $\lim_{\theta \rightarrow 0} \cos\theta - \sin \frac{\theta}{2} = \cos 0 - \sin 0 = 1$,
    \begin{eqnarray*}
      \lim_{\theta \rightarrow 0^+}\frac{\sin \theta}{\theta} = 1
    \end{eqnarray*}
    As $\frac{\sin(-\theta)}{-\theta} = \frac{\sin \theta}{\theta}$, this can be extended to $\theta < 0$.
    QED.

However this proof is based on an assumption about distances which is actually not so straightforward.
Instead, it is possible to reason about the areas of a similar figure:

* The area of a right triangle with angle :math:`\theta` and hypothenuse 1 is :math:`\frac{\cos\theta \sin\theta}{2}`
* The area of a portion of a disc of radius 1 delimited by angle :math:`\theta` is :math:`\frac{\theta}{2}` (in radians)
* The area of a right triandle with angle :math:`\theta` and side 1 next to it is :math:`\frac{\tan\theta}{2}`

.. raw:: latex

    \begin{eqnarray*}
      \frac{\cos\theta \sin\theta}{2} < &\frac{\theta}{2}& < \frac{\tan\theta}{2} \\
      \cos\theta \frac{\sin\theta}{\theta} < 1 & \text{ and } & \cos\theta < \frac{\sin\theta}{\theta} \\
      \cos\theta &<& \frac{\sin\theta}{\theta} < 1
    \end{eqnarray*}

    As $\lim_{\theta \rightarrow 0} \cos\theta = \cos 0 = 1$,
    \begin{eqnarray*}
      \lim_{\theta \rightarrow 0^+}\frac{\sin \theta}{\theta} = 1
    \end{eqnarray*}
    And like the previous proof, this can be extended to $\theta < 0$.
    QED.

This allows to compute the derivative of trigonometric functions.

.. raw:: latex

    \begin{eqnarray*}
      \frac{\sin(x + h) - \sin x}{h} &=& \frac{2}{h} \cos \frac{2x + h}{2} \sin \frac{h}{2}
        = \cos\left(x + \frac{h}{2}\right) \frac{2}{h}\sin \frac{h}{2} \\
      \frac{\cos(x + h) - \cos x}{h} &=& \frac{-2}{h} \sin \frac{2x + h}{2} \sin \frac{h}{2}
        = -\sin\left(x + \frac{h}{2}\right) \frac{2}{h}\sin \frac{h}{2}
    \end{eqnarray*}

The sine and cosine functions are infinitively derivable on :math:`\R` and :math:`\sin'(x) = \cos x` and :math:`\cos'(x) = -\sin(x)`.

.. raw:: latex

    \begin{eqnarray}
      \sin'(x) &=& \cos x \\
      \cos'(x) &=& -\sin x
    \end{eqnarray}

    As $\tan'(x) = \frac{\sin'(x) \cos x - \sin x \cos'(x)}{\cos^2 x} = \frac{\cos^2 x + \sin^2x}{\cos^2 x}$,
    \begin{equation}
      \tan'(x) = 1 + \tan^2 x = \frac{1}{\cos^2 x}
    \end{equation}

Knowing this, it is starightforward to prove that:

* :math:`\sin` is bijective between :math:`\left[-\frac{\pi}{2}, \frac{\pi}{2}\right]` and :math:`[-1, 1]`. Its reciprocal is named :math:`\arcsin`.
* :math:`\cos` is bijective between :math:`[0, \pi]` and :math:`[-1, 1]`. Its reciprocal is named :math:`\arccos`.
  (:math:`\arccos x = \frac{\pi}{2} - \arcsin x`)
* :math:`\tan` is bijective between :math:`\left]-\frac{\pi}{2}, \frac{\pi}{2}\right[` and :math:`\R`. Its reciprocal is named :math:`\arcsin`.

These new functions are infinitively derivable on either :math:`]-1, 1[` or :math:`\R` and:

* :math:`\forall x \in ]-1, 1[, \arcsin'(x) = \frac{1}{\cos(\arcsin x)} = \frac{1}{\sqrt{1 - x^2}}`
* :math:`\forall x \in ]-1, 1[, \arccos'(x) = \frac{1}{-\sin(\arccos x)} = -\frac{1}{\sqrt{1 - x^2}}`
* :math:`\forall x \in \R, \arctan'(x) = \cos^2 (\arctan x) = \frac{1}{1 + x^2}`


Link to exponential function
----------------------------

The exponential function is defined as the unique function that verifies:

* :math:`\exp(0) = 1`
* :math:`\forall x \in \R, \exp'(x) = \exp(x)`

This function obeys an exponential relationship: :math:`\exp(x + y) = \exp(x)\exp(y)` (this can be proven by studying :math:`x \mapsto \frac{\exp(x + y)}{\exp(y)}` for any :math:`y`).

The exponential function is the reciproqual of the logarithm function defined as :math:`\ln: x \in ]0, +\infty[ \mapsto \int_1^x \frac{1}{t} dt`.

It can be shown that the function is the limit of an infinite sum:

.. raw:: latex

    \begin{equation}
      \forall x \in \R, \exp(x) = \sum_{n=0}^\infty \frac{x^n}{n!} \text{ (with $0^0 = 1$)}
    \end{equation}

Using some convergence theorems, this definition can be extended to complex numbers:

.. raw:: latex

    \begin{equation}
      \forall z \in \C, \exp(z) = \sum_{n=0}^\infty \frac{z^n}{n!}
    \end{equation}

With :math:`e = \exp(1)`, this function can be written as :math:`\exp(z) = e^z`.
This is how exponentiation can be defined with complex exponents.

The study of linear differential equations shows that:

* the functions that satisfy :math:`f' = f` are of the form :math:`f: x \mapsto \lambda\exp(x)`, where :math:`\lambda = f(0)`.
* the functions that satisfy :math:`f' = \alpha f` where :math:`\alpha \in \C` are of the form :math:`f: z \mapsto \lambda\exp(\alpha z)`, where :math:`\lambda = f(0)`.

With :math:`f: \theta \mapsto \cos\theta + i \sin\theta`, :math:`f(0) = 1` and :math:`f' = -\sin + i\cos = if`.
This is why:

.. raw:: latex

    \begin{equation}
      \forall \theta \in \R, \exp(i\theta) = \cos\theta + i \sin\theta
    \end{equation}

* The module of this number is: :math:`\left|e^{i\theta}\right| = \sqrt{\cos^2\theta + \sin^2\theta} = 1`.
* :math:`e^{i\pi/2} = i`
* :math:`e^{i\pi} = -1`
* :math:`\forall k \in \Z, e^{2ik\pi} = 1` and :math:`e^{i(2k\pi + \theta)} = e^{i\theta}`

This also enables defining the cosine and the sine functions as the real and imaginary parts of the infinite sum defining :math:`e^{i\theta}`:

.. raw:: latex

    \begin{eqnarray}
      \forall \theta \in \R,
      \cos(\theta) = \frac{e^{i\theta} + e^{-i\theta}}{2} &=&
        \sum_{n=0}^\infty (-1)^n\frac{\theta^{2n}}{(2n)!} = 1 - \frac{\theta^2}{2} + \frac{\theta^4}{24} + ... \\
      \sin(\theta) = \frac{e^{i\theta} - e^{-i\theta}}{2i} &=&
        \sum_{n=0}^\infty (-1)^n\frac{\theta^{2n+1}}{(2n+1)!} = \theta - \frac{\theta^3}{6} + \frac{\theta^5}{120} + ...
    \end{eqnarray}
