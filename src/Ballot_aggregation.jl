# 8. Correctness of Ballot Aggregation

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Ballot_aggregation

Ensure the tally is the sum of the individual votes.

The code uses mapreduce to extract votes from each ballot contest
selection and then combines all of the results to produce an answer.
"""
module Ballot_aggregation

using ..Datatypes
using ..Answers
using ..Utils
using ..Parallel_mapreduce

export verify_ballot_aggregation

"8. Correctness of Ballot Aggregation"
function verify_ballot_aggregation(er::Election_record)::Answer
    acc = 0                     # Accumulated bit items
    count = 0                   # Records checked
    failed = 0
    # for each contest
    for (_, c) in er.encrypted_tally.contests
        # for each selection in contest
        for (_, sel) in c.selections
            count += 1
            sum = sum_votes(er, c.object_id, sel.object_id)
            mismatch = false
            if sum.pad != sel.ciphertext.pad
                mismatch = true
                acc |= A
            end
            if sum.data != sel.ciphertext.data
                mismatch = true
                acc |= B
            end
            if mismatch
                failed += 1
            end
        end
    end
    if failed == 0
        comment = "Tally aggregation is correct."
    else
        name = er.tally.tally_id
        comment = "Tally $name ballot aggregation is incorrect."
    end
    answer(8, bits2items(acc), "Correctness of ballot aggregation",
           comment, count, failed)
end

# Sum votes for each ballot.
function sum_votes(er::Election_record,
                   contest::String,
                   selection::String,
                   )::Ciphertext
    pmapreduce(ballot -> vote(er, contest, selection, ballot),
               (v1, v2) -> prod_ct(v1, v2, er.constants.p),
              er.submitted_ballots)
end

function vote(er::Election_record,
              contest::String,
              selection::String,
              ballot::Submitted_ballot)::Ciphertext
    if !haskey(er.spoiled_ballots, ballot.code)
        encrypted_vote(contest, selection, ballot)
    else
        one_ct
    end
end

# Return the encrypted vote or one if it is missing.
function encrypted_vote(contest::String,
                        selection::String,
                        ballot::Submitted_ballot
                        )::Ciphertext
    # Find contest
    for c in ballot.contests
        if c.object_id == contest
            # Find selection
            for sel in c.ballot_selections
                if sel.object_id == selection
                    return sel.ciphertext
                end
            end
            # No selection found
            return one_ct
        end
    end
    # No contest found
    one_ct
end

end
