\usepackage{bbm}
\usepackage{stmaryrd}
\usepackage{tikz}
\usetikzlibrary{angles,quotes}

% Define math shortcuts
\ifcsname{C}\endcsname%
  \renewcommand{\C}[0]{\ensuremath{\mathbbm{C}}}
\else%
  \newcommand{\C}[0]{\ensuremath{\mathbbm{C}}}
\fi
\newcommand{\N}[0]{\ensuremath{\mathbbm{N}}}
\newcommand{\Ns}[0]{\ensuremath{\mathbbm{N^{*}}}}
\newcommand{\Z}[0]{\ensuremath{\mathbbm{Z}}}
\newcommand{\Zs}[0]{\ensuremath{\mathbbm{Z^{*}}}}
\newcommand{\Primes}[0]{\ensuremath{\mathbbm{P}}}
\newcommand{\F}[1]{\ensuremath{\mathbbm{F}_{#1}}}
\newcommand{\R}[0]{\ensuremath{\mathbbm{R}}}
\newcommand{\ord}[0]{\ensuremath{\text{ord}}}
\DeclareMathOperator{\Ker}{Ker}
\DeclareMathOperator{\Img}{Im}

\newtheorem{theorem}{Theorem}
\newtheorem{definition}{Definition}
