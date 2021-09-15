\usepackage{bbm}
\usepackage{stmaryrd}
\usepackage{tikz}
\usetikzlibrary{angles,quotes}

% Define math shortcuts
% When using unicode, \C is defined in texmf-dist/tex/latex/hyperref/puenc.def
% as: \DeclareTextCommand{\C}{PU}[1]{#1\83\017}% U+030F
% which is Unicode "COMBINING DOUBLE GRAVE ACCENT".
% This character is also available through \textdoublegrave
% ( \show\C displays:
%       > \C=macro:
%       ->\PU-cmd \C \PU\C .
% )
\providecommand{\C}{}
\renewcommand{\C}[0]{\ensuremath{\mathbbm{C}}}
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
