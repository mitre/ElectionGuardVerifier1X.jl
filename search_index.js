var documenterSearchIndex = {"docs":
[{"location":"results.html#Results","page":"Results","title":"Results","text":"","category":"section"},{"location":"results.html","page":"Results","title":"Results","text":"The check function implements what is described in the ElectionGuard specification. The MITRE ElectionGuard Verifier produces output for each verifier step. The numbers in the output correspond to the steps listed.  For example, the line of output that says:","category":"page"},{"location":"results.html","page":"Results","title":"Results","text":"1. Standard parameters were found.","category":"page"},{"location":"results.html","page":"Results","title":"Results","text":"is the result of performing the check described in Step 1.","category":"page"},{"location":"results.html","page":"Results","title":"Results","text":"The output provides additional information when a verification step fails.  Many verification steps specify an enumeration of checks, each labeled by a capital letter.  When a step fails, the letters associated with failed checks are listed after the step number.  So an output line that starts with","category":"page"},{"location":"results.html","page":"Results","title":"Results","text":"9CD. Bla bla...","category":"page"},{"location":"results.html","page":"Results","title":"Results","text":"means the check associated with items 9.C and 9.D failed.  Many checks inspect more than one record.  If say Item C only fails on one record, and Item D only fails on another, both Items will be reported.","category":"page"},{"location":"results.html","page":"Results","title":"Results","text":"When more than one record fails during a check, the comment associated with the failures is non-deterministically picked from one of the failures.","category":"page"},{"location":"results.html#Sample-Output","page":"Results","title":"Sample Output","text":"","category":"section"},{"location":"results.html","page":"Results","title":"Results","text":"Loading jefferson-county-primary.\nFound 1.0 election records as expected.\njefferson-county-primary\n 1. Standard parameters were found.\n 2. Guardian pubkeys are valid.\n 3. Election pubkey is valid.\n 4. Extended base hash is valid.\n 5. Selection encryptions are valid.\n 7. No duplicate confirmation codes found.\n 8. Tally aggregation is correct.\n 9C. Tally decryptions are incorrect.\n    6 records failed out of 6 total.\n10. Tally selections agree with the manifest.\n12C. Spoiled ballot 3CD7AC6425443D2068C64435A55768F8AD10CA3A123291A1CAC4C127EA9CA7F2 decryptions are incorrect.\n    6 records failed out of 6 total.\n13. Spoiled ballot 3CD7AC6425443D2068C64435A55768F8AD10CA3A123291A1CAC4C127EA9CA7F2 selections agree with the manifest.\n12C. Spoiled ballot 1C8DB0B7972C8E0456B1300F8F8D594E6634C4EDBFD9E71379989713D0FFEF6E decryptions are incorrect.\n    6 records failed out of 6 total.\n13. Spoiled ballot 1C8DB0B7972C8E0456B1300F8F8D594E6634C4EDBFD9E71379989713D0FFEF6E selections agree with the manifest.\nfalse","category":"page"},{"location":"results.html","page":"Results","title":"Results","text":"For this run false says the verification failed.  Scanning farther up in the output, you see that Steps 9C and 12C are the steps that failed.","category":"page"},{"location":"results.html#Step-Relabeling","page":"Results","title":"Step Relabeling","text":"","category":"section"},{"location":"results.html","page":"Results","title":"Results","text":"In order to reuse code, the verifier uses different letters for step 13.","category":"page"},{"location":"results.html","page":"Results","title":"Results","text":"13.B instead of 13.D\n13.C instead of 13.E\n13.D instead of 13.F\n13.F instead of 13.B\n13.G instead of 13.C","category":"page"},{"location":"results.html#Verification-Record-as-JSON","page":"Results","title":"Verification Record as JSON","text":"","category":"section"},{"location":"results.html","page":"Results","title":"Results","text":"When the check method is called with an addition string, the string names the path of an output file used to store the verification record in JSON format.  The record has the following form.","category":"page"},{"location":"results.html","page":"Results","title":"Results","text":"spec_version [string] ElectionGuard specification version\nelection_scope_id [string] Election identifier\nstart_date [ISO date time as string] Start time of election\nend_date [ISO date time as string] End time of election\nverifier [string] Name of verifier\nrun_date [UTC ISO date time as string] Verifier run time\nverified [boolean] Did election record verify?\nanswers [list of answer] Verification results","category":"page"},{"location":"results.html","page":"Results","title":"Results","text":"Each answer has the following form.","category":"page"},{"location":"results.html","page":"Results","title":"Results","text":"step [int] Verification step number\nitems [string] Verification items in a step that failed ('X' is used when the step has no enumerated items.)\nsection [string] Step section title\ncomment [string] Result comment\ncount [int] Number of records checked\nfailed [int] Number of checks that failed","category":"page"},{"location":"results.html#Example","page":"Results","title":"Example","text":"","category":"section"},{"location":"results.html","page":"Results","title":"Results","text":"{\n  \"spec_version\": \"v0.95\",\n  \"election_scope_id\": \"jefferson-county-primary\",\n  \"start_date\": \"2020-03-01T08:00:00-05:00\",\n  \"end_date\": \"2020-03-01T20:00:00-05:00\",\n  \"verifier\": \"MITRE ElectionGuard Verifier\",\n  \"run_date\": \"2022-05-27T20:54:14.689\",\n  \"verified\": false,\n  \"answers\": [\n    {\n      \"step\": 1,\n      \"items\": \"\",\n      \"section\": \"Parameter verification\",\n      \"comment\": \"Standard parameters were found.\",\n      \"count\": 1,\n      \"failed\": 0\n    },\n    {\n      \"step\": 2,\n      \"items\": \"\",\n      \"section\": \"Guardian public-key validation\",\n      \"comment\": \"Guardian pubkeys are valid.\",\n      \"count\": 5,\n      \"failed\": 0\n    },\n    {\n      \"step\": 3,\n      \"items\": \"B\",\n      \"section\": \"Election public-key validation\",\n      \"comment\": \"Election pubkey is invalid.\",\n      \"count\": 1,\n      \"failed\": 1\n    },\n    ...\n  ]\n}","category":"page"},{"location":"results.html#Election-Record-Loading-Failures","page":"Results","title":"Election Record Loading Failures","text":"","category":"section"},{"location":"results.html","page":"Results","title":"Results","text":"If the MITRE ElectionGuard Verifier receives an election record that is not well formed, the program prints","category":"page"},{"location":"results.html","page":"Results","title":"Results","text":"Error loading the election record at PATH","category":"page"},{"location":"results.html","page":"Results","title":"Results","text":"where PATH is the location of the election record loaded.  It then prints a stack trace for experience Julia programmers that identifies the cause of the loading failure.","category":"page"},{"location":"usage.html#Usage","page":"Usage","title":"Usage","text":"","category":"section"},{"location":"usage.html","page":"Usage","title":"Usage","text":"To run the verifier, change your directory to the location of the election records.  It's the directory that contains a manifest.json file.","category":"page"},{"location":"usage.html","page":"Usage","title":"Usage","text":"Start the Julia interpreter with\n$ julia --threads=auto\nLoad the verifier with\njulia> using ElectionGuardVerifier1X\nLoad and then check the election records with\njulia> validate(\".\")\nThe final line of output is true if the election records pass all tests, otherwise it is false.\nExit Julia with exit() or type cntl-D.","category":"page"},{"location":"development.html#Development","page":"Development","title":"Development","text":"","category":"section"},{"location":"development.html","page":"Development","title":"Development","text":"CurrentModule = ElectionGuardVerifier1X","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"This section introduces the source code that makes up the verifier. According to C.A.R Hoare:","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"There are two ways of constructing a software design.  One way is to make it so simple that there are obviously  no deficiencies.  And the other way is to make it so  complicated that there are no obvious deficiencies.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"Our goal is to always write code that is obviously correct.","category":"page"},{"location":"development.html#Introduction","page":"Development","title":"Introduction","text":"","category":"section"},{"location":"development.html","page":"Development","title":"Development","text":"To get the most out of this tour, view the relevant sources as you read each section.  The tour begins with the datatypes that reflect the contents of an election record followed by the procedures used to load an election record into those datatypes.  Common utilities used to implement ElectionGuard checks is next.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"Pay close attention to the section on answers, as it describes how check failures are linked to the section in the specification where the check is specified.  The Check section describes the top-level loop used to drive the verification process.  Finally, the section on verification routes describes how individual checks are implemented.","category":"page"},{"location":"development.html#Datatypes","page":"Development","title":"Datatypes","text":"","category":"section"},{"location":"development.html","page":"Development","title":"Development","text":"The way to understand the software is to start by viewing the Datatypes module.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"Datatypes","category":"page"},{"location":"development.html#ElectionGuardVerifier1X.Datatypes","page":"Development","title":"ElectionGuardVerifier1X.Datatypes","text":"Datatypes\n\nThis module contains the structures that appear in the JSON data files that make up an ElectionGuard election record.  The field names in structs are the field names that appear in the JSON file with the exception of constants.  The use of constants is too ubiquitous to use the verbose field names.\n\nTo see the structure of the data, it is best that you read the structs in this file in reverse order.\n\n\n\n\n\n","category":"module"},{"location":"development.html#Loader","page":"Development","title":"Loader","text":"","category":"section"},{"location":"development.html","page":"Development","title":"Development","text":"The loader describes the expected directory structure of an election record.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"Loader\nload(path::AbstractString)","category":"page"},{"location":"development.html#ElectionGuardVerifier1X.Loader","page":"Development","title":"ElectionGuardVerifier1X.Loader","text":"Loader\n\nThe loader assumes the records are delivered using a standard directory structure that is encoded here.  The structure is\n\nmanifest.json: Data about the election\nconstants.json: Constants used for ElGamal cryptography\ncontext.json: Election parameters\nguardians/*.json: Per guardian data\nsubmitted_ballots/*.json: Submitted ballots\nspoiled_ballots/*.json: Spoiled ballots (may be missing)\nencrypted_tally: Encrypted tally\ntally.json: The tally\n\n\n\n\n\n","category":"module"},{"location":"development.html#ElectionGuardVerifier1X.Loader.load-Tuple{AbstractString}","page":"Development","title":"ElectionGuardVerifier1X.Loader.load","text":"load(path::AbstractString)::Election_record\n\nLoad election records in the given directory.  On error, print load error message before crashing.\n\n\n\n\n\n","category":"method"},{"location":"development.html#Utililies","page":"Development","title":"Utililies","text":"","category":"section"},{"location":"development.html","page":"Development","title":"Development","text":"CurrentModule = ElectionGuardVerifier1X.Utils","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"Utils\nmulpowmod(a::BigInt, x::BigInt, b::BigInt, p::BigInt)\nsame(c1::Constants, c2::Constants)\nsame(c1::Ciphertext, c2::Ciphertext)\nwithin(x::BigInt, p::BigInt)\nwithin_mod\none_ct\nprod_ct(x1::Ciphertext, x2::Ciphertext, p::BigInt)","category":"page"},{"location":"development.html#ElectionGuardVerifier1X.Utils","page":"Development","title":"ElectionGuardVerifier1X.Utils","text":"Utils\n\nFunctions used to implement Election Guard checks.\n\n\n\n\n\n","category":"module"},{"location":"development.html#ElectionGuardVerifier1X.Utils.mulpowmod-NTuple{4, BigInt}","page":"Development","title":"ElectionGuardVerifier1X.Utils.mulpowmod","text":"mulpowermod(a, x, b, p) = (a * x ^ b) mod p\n\n\n\n\n\n","category":"method"},{"location":"development.html#ElectionGuardVerifier1X.Utils.same-Tuple{ElectionGuardVerifier1X.Datatypes.Constants, ElectionGuardVerifier1X.Datatypes.Constants}","page":"Development","title":"ElectionGuardVerifier1X.Utils.same","text":"same(c1::Constants, c2::Constants)::Bool\n\nAre two sets of constants the same?\n\n\n\n\n\n","category":"method"},{"location":"development.html#ElectionGuardVerifier1X.Utils.same-Tuple{ElectionGuardVerifier1X.Datatypes.Ciphertext, ElectionGuardVerifier1X.Datatypes.Ciphertext}","page":"Development","title":"ElectionGuardVerifier1X.Utils.same","text":"same(c1::Ciphertext, c2::Ciphertext)::Bool\n\nAre two ciphertexts the same?\n\n\n\n\n\n","category":"method"},{"location":"development.html#ElectionGuardVerifier1X.Utils.within-Tuple{BigInt, BigInt}","page":"Development","title":"ElectionGuardVerifier1X.Utils.within","text":"within(x::BigInt, p::BigInt)::Bool\n\nIs 0 ≤ x < p?\n\n\n\n\n\n","category":"method"},{"location":"development.html#ElectionGuardVerifier1X.Utils.within_mod","page":"Development","title":"ElectionGuardVerifier1X.Utils.within_mod","text":"within_mod(x::BigInt, q::BigInt, p::BigInt)::Bool\n\nIs 0 ≤ x < p and (x ^ q) mod p == 1?\n\n\n\n\n\n","category":"function"},{"location":"development.html#ElectionGuardVerifier1X.Utils.one_ct","page":"Development","title":"ElectionGuardVerifier1X.Utils.one_ct","text":"one_ct::Ciphertext\n\none_ct = Ciphertext(1, 1)\n\n\n\n\n\n","category":"constant"},{"location":"development.html#ElectionGuardVerifier1X.Utils.prod_ct-Tuple{ElectionGuardVerifier1X.Datatypes.Ciphertext, ElectionGuardVerifier1X.Datatypes.Ciphertext, BigInt}","page":"Development","title":"ElectionGuardVerifier1X.Utils.prod_ct","text":"prod_ct(x1::Ciphertext, x2::Ciphertext, p::BigInt)::Ciphertext\n\nMultiply two ciphertexts mod p\n\n\n\n\n\n","category":"method"},{"location":"development.html#Answers","page":"Development","title":"Answers","text":"","category":"section"},{"location":"development.html","page":"Development","title":"Development","text":"CurrentModule = ElectionGuardVerifier1X.Answers","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"Answers\nanswer(step::Int64, items::String, section::String,\n       comment::String, count::Int64, failed::Int64)\nverification_record(er::Election_record,\n                    anss::Vector{Answer})\nbits2items(bits::Int64)","category":"page"},{"location":"development.html#ElectionGuardVerifier1X.Answers","page":"Development","title":"ElectionGuardVerifier1X.Answers","text":"Answers\n\nThis module provides data structures and operations used to report verification answers.  At the top-level, there is a verification record.  It identifies the specification version, the election, and contains a list of verification answers.  A verification answer is the result of checking all or part of a verification step as defined in an ElectionGuard specification.\n\nA verification answer contains a verification step number, a string listing items that failed while verifying the step, the step title, a comment, the number of records checked, and the number of records that failed.  A failing step that has no items is marked using item \"X\".\n\nIn the verification routies, each verification item check returns an integer.  The integer is zero if the check passes, otherwise it is an integer with one bit set.  The bit is used to identify the item being checked.  The bit patterns are exported as constants A, B, C, D, E, F, G, H, I, J, and K.  The bit patterns for multiple checks are combined using bitwise or.\n\n\n\n\n\n","category":"module"},{"location":"development.html#ElectionGuardVerifier1X.Answers.answer-Tuple{Int64, String, String, String, Int64, Int64}","page":"Development","title":"ElectionGuardVerifier1X.Answers.answer","text":"Construct a step answer\n\n\n\n\n\n","category":"method"},{"location":"development.html#ElectionGuardVerifier1X.Answers.verification_record-Tuple{ElectionGuardVerifier1X.Datatypes.Election_record, Vector{ElectionGuardVerifier1X.Answers.Answer}}","page":"Development","title":"ElectionGuardVerifier1X.Answers.verification_record","text":"Construct a verification record\n\n\n\n\n\n","category":"method"},{"location":"development.html#ElectionGuardVerifier1X.Answers.bits2items-Tuple{Int64}","page":"Development","title":"ElectionGuardVerifier1X.Answers.bits2items","text":"Convert a bit pattern to items\n\n\n\n\n\n","category":"method"},{"location":"development.html#Check","page":"Development","title":"Check","text":"","category":"section"},{"location":"development.html","page":"Development","title":"Development","text":"CurrentModule = ElectionGuardVerifier1X","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"The check function implements what is described in the version 1.0 ElectionGuard Specification.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"check(er::Election_record)","category":"page"},{"location":"development.html#ElectionGuardVerifier1X.check-Tuple{ElectionGuardVerifier1X.Datatypes.Election_record}","page":"Development","title":"ElectionGuardVerifier1X.check","text":"check(er::Election_record, path::String=\"\")::Bool\n\nCheck election record.  Write answers to path in JSON if path is not empty.\n\n\n\n\n\n","category":"method"},{"location":"development.html","page":"Development","title":"Development","text":"The check function calls function verify, which returns a verification record that check optionally prints into a JSON file, and then returns the element in the record that says if all of the verification routines succeeded.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"The verify function runs each verification routine.  Each routine creates an Answer.  The verify function sequentially runs each routine, prints the result, and stores the answer for inclusion in the returned verification record.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"validate(path::AbstractString, log::String=\"\")","category":"page"},{"location":"development.html#ElectionGuardVerifier1X.validate","page":"Development","title":"ElectionGuardVerifier1X.validate","text":"validate(path::AbstractString, log::String=\"\")::Bool\n\nLoad and then check the election record in path. Write answers to log in JSON if path is not empty.\n\n\n\n\n\n","category":"function"},{"location":"development.html#Verification-Routines","page":"Development","title":"Verification Routines","text":"","category":"section"},{"location":"development.html","page":"Development","title":"Development","text":"All verification routines have a comment structure.  The structure is revealed by studying the source code for three representative routines.","category":"page"},{"location":"development.html#A-Simple-Routine","page":"Development","title":"A Simple Routine","text":"","category":"section"},{"location":"development.html","page":"Development","title":"Development","text":"The simplest routine is the one that checks for standard constants.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"CurrentModule = ElectionGuardVerifier1X.Params","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"Params","category":"page"},{"location":"development.html#ElectionGuardVerifier1X.Params","page":"Development","title":"ElectionGuardVerifier1X.Params","text":"Params\n\nEnsure the constants are the standard ones.\n\n\n\n\n\n","category":"module"},{"location":"development.html","page":"Development","title":"Development","text":"The specification for this routine has no items and there is only one check required.  Notice the items field in the answer is always the empty string.","category":"page"},{"location":"development.html#A-Routine-That-Checks-a-Small-Number-of-Records","page":"Development","title":"A Routine That Checks a Small Number of Records","text":"","category":"section"},{"location":"development.html","page":"Development","title":"Development","text":"The following routine checks each guardian.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"CurrentModule = ElectionGuardVerifier1X.Guardian_pubkey","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"Guardian_pubkey","category":"page"},{"location":"development.html#ElectionGuardVerifier1X.Guardian_pubkey","page":"Development","title":"ElectionGuardVerifier1X.Guardian_pubkey","text":"Guardian_pubkey\n\nVerify the correct computation of the joint election public key and extended base hash.\n\n\n\n\n\n","category":"module"},{"location":"development.html","page":"Development","title":"Development","text":"There are two checks in the specification labeled as Item A, and Item B.  The check for each item returns an integer that is zero when the check succeeds.  When a check is non-zero, it returns a bit pattern that reveals which item failed.  The main loop accumulates the bit patterns in the acc variable, which is used to produce the items field in the answer.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"When there are multiple failures, the comment returned as an answer is the one generated by one of the failures.  In this case, it will be the last failure.","category":"page"},{"location":"development.html#A-Routine-That-Checks-Each-Submitted-Ballot","page":"Development","title":"A Routine That Checks Each Submitted Ballot","text":"","category":"section"},{"location":"development.html","page":"Development","title":"Development","text":"The following routine checks each submitted ballot.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"CurrentModule = ElectionGuardVerifier1X.Selection_encryptions","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"Selection_encryptions","category":"page"},{"location":"development.html#ElectionGuardVerifier1X.Selection_encryptions","page":"Development","title":"ElectionGuardVerifier1X.Selection_encryptions","text":"Selection_encryptions\n\nEnsure the selection encryptions in each ballot are valid.\n\nThe code uses mapreduce to apply a check to each ballot and then combines all of the results to produce an answer.\n\n\n\n\n\n","category":"module"},{"location":"development.html","page":"Development","title":"Development","text":"This check is one of the most complicated verification routes, however, its computation is quite similar to what occurs in the previous routine with one exception, the routine is structured so its results can be computed with mapreduce.  Mapreduce provides a means to encode embarrassingly parallel computations in a way that can be easily exploited by concurrent hardware.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"Mapreduce(f op vec) applies unary function fAto B to each element in vector vecA^ast, and then binary function opBtimes Bto B is used to reduce every value computed by f into a single value of type B that is returned.  During the reduction process, the order in which pairs of values are reduced to one is unspecified, and therefore to produce a deterministic value, op must be associative.  A thread parallel implementation of mapreduce follows.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"CurrentModule = ElectionGuardVerifier1X.Parallel_mapreduce","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"pmapreduce","category":"page"},{"location":"development.html#ElectionGuardVerifier1X.Parallel_mapreduce.pmapreduce","page":"Development","title":"ElectionGuardVerifier1X.Parallel_mapreduce.pmapreduce","text":"pmapreduce(f, op, vec::AbstractVector)\n\nWhen Julia is started with enough threads, this version of mapreduce divides a vector into into sections, runs mapreduce on each section in parallel, and then collects the results using the op function.\n\n\n\n\n\n","category":"function"},{"location":"development.html","page":"Development","title":"Development","text":"For the verification routine, type A is the type of a submitted ballot, and type B is the structure Accum.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"CurrentModule = ElectionGuardVerifier1X.Selection_encryptions","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"Accum","category":"page"},{"location":"development.html#ElectionGuardVerifier1X.Selection_encryptions.Accum","page":"Development","title":"ElectionGuardVerifier1X.Selection_encryptions.Accum","text":"Accum\n\nAccumulated value type for mapreduce\n\n\n\n\n\n","category":"type"},{"location":"development.html","page":"Development","title":"Development","text":"Notice it contains what is needed to produce an answer.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"Function op is implemented by function combine.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"combine","category":"page"},{"location":"development.html#ElectionGuardVerifier1X.Selection_encryptions.combine","page":"Development","title":"ElectionGuardVerifier1X.Selection_encryptions.combine","text":"combine(accum1::Accum, accum2::Accum)\n\nCombine accumulated values.\n\n\n\n\n\n","category":"function"},{"location":"development.html","page":"Development","title":"Development","text":"Notice that combine is not associative, and therefore the output of a call to mapreduce using it is not deterministic.  This is because the comment returned by mapreduce is allowed to be the one associated with any failure.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"The function f is constructed using the following.","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"verify_ballot(er::Election_record, ballot::Submitted_ballot)","category":"page"},{"location":"development.html#ElectionGuardVerifier1X.Selection_encryptions.verify_ballot-Tuple{ElectionGuardVerifier1X.Datatypes.Election_record, ElectionGuardVerifier1X.Datatypes.Submitted_ballot}","page":"Development","title":"ElectionGuardVerifier1X.Selection_encryptions.verify_ballot","text":"verify_ballot(er::Election_record, ballot::Submitted_ballot)\n\nVerify one ballot.\n\n\n\n\n\n","category":"method"},{"location":"development.html","page":"Development","title":"Development","text":"The actual call is to mapreduce is","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"accum = pmapreduce(ballot -> verify_ballot(er, ballot),\n                   combine, er.submitted_ballots)","category":"page"},{"location":"development.html","page":"Development","title":"Development","text":"where er is a variable captured from the environment of the call.","category":"page"},{"location":"installation.html#Installation","page":"Installation","title":"Installation","text":"","category":"section"},{"location":"installation.html","page":"Installation","title":"Installation","text":"The MITRE ElectionGuard Verifier is written in the Julia programming language.  Follow the instructions at the Julia web site to download and install the system on your computer.","category":"page"},{"location":"installation.html","page":"Installation","title":"Installation","text":"MITRE ElectionGuard Verifier can be installed using the Julia package manager. From the Julia REPL, type ] to enter the Pkg REPL mode and run","category":"page"},{"location":"installation.html","page":"Installation","title":"Installation","text":"pkg> add https://github.com/mitre/ElectionGuardVerifier1X.jl","category":"page"},{"location":"installation.html","page":"Installation","title":"Installation","text":"Type the delete key or cntl-C to exit the Pkg REPL mode.","category":"page"},{"location":"installation.html","page":"Installation","title":"Installation","text":"The Pkg command update can be used to ensure the latest version of the verifier is installed.","category":"page"},{"location":"index.html#MITRE-ElectionGuard-Verifier","page":"Home","title":"MITRE ElectionGuard Verifier","text":"","category":"section"},{"location":"index.html","page":"Home","title":"Home","text":"John D. Ramsdell and Moses D. Liskov","category":"page"},{"location":"index.html","page":"Home","title":"Home","text":"ElectionGuard is a software system designed to make voting more secure, transparent and accessible. ElectionGuard uses cryptography to ensure that","category":"page"},{"location":"index.html","page":"Home","title":"Home","text":"voters can verify that their own selections have been correctly recorded, and\nanyone can verify that the recorded votes have been correctly tallied.","category":"page"},{"location":"index.html","page":"Home","title":"Home","text":"Version 1.91 of the MITRE ElectionGuard Verifier provides the means to validate specification in an easy to use package.","category":"page"},{"location":"index.html#Design-Goals","page":"Home","title":"Design Goals","text":"","category":"section"},{"location":"index.html","page":"Home","title":"Home","text":"Our primary goal is to write easily understood correct code. We follow Donald Knuth advice's on writing software:","category":"page"},{"location":"index.html","page":"Home","title":"Home","text":"Instead of imagining that our main task is to instruct a  computer what to do, let us concentrate rather on  explaining to human beings what we want a computer to do.","category":"page"},{"location":"index.html","page":"Home","title":"Home","text":"We have two secondary goals.","category":"page"},{"location":"index.html","page":"Home","title":"Home","text":"When the verifier detects a problem with a part of an election record, it provides a clear link to the equations in the spec that where violated by the election record, thereby easing the task of diagosing what went wrong.\nThe verifier makes effective use of parallel processing without contradicting our pledge to write easily understood corret code.","category":"page"}]
}
