+++
date = '2026-03-26T20:01:07+01:00'
draft = false
title = 'Crayon_cochon'
+++

## Attachments

Note : Le flag ne suit aucun format de flag.

Cette épreuve avait été proposée lors de l’entrainement de la Team France en septembre 2019.

![crayon-cochon](crayon-cochon.png)

## Reverse

Nothing interesting, neither with exiftool, strings, file or whatever.
We need to decode the weird string on the photo but how ...?
Let's map the string

<table style="border-collapse: collapse; font-family: monospace;">
<tr>U        => A</tr><br>
<tr>O        => B</tr><br>
<tr>L.       => C</tr><br>
<tr>C.       => D</tr><br>
<tr>V.       => E</tr><br>
<tr></tr><br>
<tr>r        => F</tr><br>
<tr>V        => G</tr><br>
<tr></tr><br>
<tr>p        => H</tr><br>
<tr>n        => I</tr><br>
<tr>O        => B</tr><br>
<tr></tr><br>
<tr>C        => J</tr><br>
<tr>L.       => C</tr><br>
<tr>Linv     => K</tr><br>
<tr>rinv     => L</tr><br>
<tr></tr><br>
<tr>U.       => M</tr><br>
<tr>C        => J</tr><br>
<tr>O.       => N</tr><br>
<tr>C.       => D</tr><br>
<tr>U.       => M</tr><br>
<tr>U        => A</tr><br>
<tr>n        => I</tr><br>
<tr>Cinv     => O</tr><br>
<tr>U        => A</tr><br>
<tr>L.       => C</tr><br>
<tr>O        => B</tr><br>
<tr>U        => A</tr><br>
<tr>V        => G</tr><br>
<tr>A        => P</tr><br>
<tr>Linv.    => Q</tr><br>
<tr>Cinv.    => R</tr><br>
<tr>r.       => S</tr><br>
<tr>p.       => T</tr><br>
<tr>U.       => M</tr><br>
<tr>pinv.    => U</tr><br>
<tr>C.       => D</tr><br>
<tr>p.       => T</tr><br>
<tr>Cinv     => O</tr><br>
<tr>n.       => V</tr><br>
<tr>A.       => W</tr><br>
<tr>Linv     => K</tr><br>
<tr>O        => B</tr><br>
<tr>Linv     => K</tr><br>
<tr>n        => I</tr><br>


</table>

S = "ABCDE FG HIB JCKL MJNDMAIOACBAGPQRSTMUDTOVWKBKI"

As the description says, the flag hasn't particular format so it's impossible to bruteforce a mono-alphabetic substitution.

After searching the web, it's a "cipher" known under the name "Chiffre des francs-maçons" and the substitution is as follow:


## Solve
"BELOW IS THE FLAG KFNOKBHDBLEBSVJMRXKYOXDQZAEAH"

Maybe sometimes the best thing to do is to directly search on internet.. or request an AI.


Thx.

Sk4r.