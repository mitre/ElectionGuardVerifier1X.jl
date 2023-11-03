# Results

The `check` function implements what is described in the ElectionGuard
[specification](https://www.electionguard.vote/elections/College_Park_Maryland_2023/).
The MITRE ElectionGuard Verifier produces output for each verifier
step. The numbers in the output correspond to the steps listed.  For
example, the line of output that says:

```
1. Standard parameters were found.
```

is the result of performing the check described in Step 1.

The output provides additional information when a verification step
fails.  Many verification steps specify an enumeration of checks, each
labeled by a capital letter.  When a step fails, the letters
associated with failed checks are listed after the step number.  So an
output line that starts with

```
9CD. Bla bla...
```

means the check associated with items 9.C and 9.D failed.  Many checks
inspect more than one record.  If say Item C only fails on one record,
and Item D only fails on another, both Items will be reported.

When more than one record fails during a check, the comment associated
with the failures is non-deterministically picked from one of the
failures.

### Sample Output

```
Loading jefferson-county-primary.
Found 1.0 election records as expected.
jefferson-county-primary
 1. Standard parameters were found.
 2. Guardian pubkeys are valid.
 3. Election pubkey is valid.
 4. Extended base hash is valid.
 5. Selection encryptions are valid.
 7. No duplicate confirmation codes found.
 8. Tally aggregation is correct.
 9C. Tally decryptions are incorrect.
    6 records failed out of 6 total.
10. Tally selections agree with the manifest.
12C. Spoiled ballot 3CD7AC6425443D2068C64435A55768F8AD10CA3A123291A1CAC4C127EA9CA7F2 decryptions are incorrect.
    6 records failed out of 6 total.
13. Spoiled ballot 3CD7AC6425443D2068C64435A55768F8AD10CA3A123291A1CAC4C127EA9CA7F2 selections agree with the manifest.
12C. Spoiled ballot 1C8DB0B7972C8E0456B1300F8F8D594E6634C4EDBFD9E71379989713D0FFEF6E decryptions are incorrect.
    6 records failed out of 6 total.
13. Spoiled ballot 1C8DB0B7972C8E0456B1300F8F8D594E6634C4EDBFD9E71379989713D0FFEF6E selections agree with the manifest.
false
```

For this run `false` says the verification failed.  Scanning farther
up in the output, you see that Steps 9C and 12C are the steps that
failed.

### Step Relabeling

In order to reuse code, the verifier uses different letters for step 13.

 * 13.B instead of 13.D
 * 13.C instead of 13.E
 * 13.D instead of 13.F
 * 13.F instead of 13.B
 * 13.G instead of 13.C

## Verification Record as JSON

When the `check` method is called with an addition string, the string
names the path of an output file used to store the verification record
in JSON format.  The record has the following form.

- `spec_version` [string] ElectionGuard specification version

- `election_scope_id` [string] Election identifier

- `start_date` [ISO date time as string] Start time of election

- `end_date` [ISO date time as string] End time of election

- `verifier` [string] Name of verifier

- `run_date` [UTC ISO date time as string] Verifier run time

- `verified` [boolean] Did election record verify?

- `answers` [list of answer] Verification results

Each answer has the following form.

- `step` [int] Verification step number

- `items` [string] Verification items in a step that failed ('X' is
  used when the step has no enumerated items.)

- `section` [string] Step section title

- `comment` [string] Result comment

- `count` [int] Number of records checked

- `failed` [int] Number of checks that failed

### Example

```
{
  "spec_version": "v0.95",
  "election_scope_id": "jefferson-county-primary",
  "start_date": "2020-03-01T08:00:00-05:00",
  "end_date": "2020-03-01T20:00:00-05:00",
  "verifier": "MITRE ElectionGuard Verifier",
  "run_date": "2022-05-27T20:54:14.689",
  "verified": false,
  "answers": [
    {
      "step": 1,
      "items": "",
      "section": "Parameter verification",
      "comment": "Standard parameters were found.",
      "count": 1,
      "failed": 0
    },
    {
      "step": 2,
      "items": "",
      "section": "Guardian public-key validation",
      "comment": "Guardian pubkeys are valid.",
      "count": 5,
      "failed": 0
    },
    {
      "step": 3,
      "items": "B",
      "section": "Election public-key validation",
      "comment": "Election pubkey is invalid.",
      "count": 1,
      "failed": 1
    },
    ...
  ]
}
```

## Election Record Loading Failures

If the MITRE ElectionGuard Verifier receives an election record that
is not well formed, the program prints

```
Error loading the election record at PATH
```

where PATH is the location of the election record loaded.  It then
prints a stack trace for experience Julia programmers that identifies
the cause of the loading failure.
