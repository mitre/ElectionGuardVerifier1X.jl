# Usage

To run the verifier, change your directory to the location of the
election records.  It's the directory that contains a `manifest.json`
file.

 1. Start the Julia interpreter with

    ```sh
    $ julia --threads=auto
    ```

 2. Load the verifier with

    ```julia
    julia> using ElectionGuardVerifier1X
    ```

 3. Load and then check the election records with

    ```julia
    julia> validate(".")
    ```

    The final line of output is `true` if the election records pass
    all tests, otherwise it is `false`.

 4. Exit Julia with `exit()` or type cntl-D.
