# MITRE ElectionGuard Verifier

John D. Ramsdell and Moses D. Liskov

[ElectionGuard](https://www.electionguard.vote/) is a software system
designed to make voting more secure, transparent and accessible.
ElectionGuard uses cryptography to ensure that

 - voters can verify that their own selections have been correctly
   recorded, and

 - anyone can verify that the recorded votes have been correctly
   tallied.

Version 1.91 of the MITRE ElectionGuard Verifier provides the means
to validate
[specification](https://www.electionguard.vote/elections/College_Park_Maryland_2023/)
in an easy to use package.

## Design Goals

Our primary goal is to write easily understood correct code.
We follow Donald Knuth advice's on writing software:

>  Instead of imagining that our main task is to instruct a
>  *computer* what to do, let us concentrate rather on
>  explaining to *human beings* what we want a computer to do.

We have two secondary goals.

 - When the verifier detects a problem with a part of an election
   record, it provides a clear link to the equations in the spec that
   where violated by the election record, thereby easing the task of
   diagosing what went wrong.

 - The verifier makes effective use of parallel processing without
   contradicting our pledge to write easily understood corret code.
