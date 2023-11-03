# 5. Correctness of Selection Encryptions

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Selection_encryptions

Ensure the selection encryptions in each ballot are valid.

The code uses mapreduce to apply a check to each ballot and then
combines all of the results to produce an answer.
"""
module Selection_encryptions

using ..Datatypes
using ..Answers
using ..Utils
using ..Parallel_mapreduce
using ..Hash

export verify_selection_encryptions

"5. Correctness of Selection Encryptions"
function verify_selection_encryptions(er::Election_record)::Answer
    accum = pmapreduce(ballot -> verify_ballot(er, ballot),
                       combine, er.submitted_ballots)
    comment = accum.comment
    if comment == ""
        comment = "Selection encryptions are valid."
    end
    answer(5, bits2items(accum.acc), "Correctness of selection encryption",
           comment, accum.count, accum.failed)
end

"""
    Accum

Accumulated value type for mapreduce
"""
struct Accum
    comment::String             # Answer comment
    acc::Int64                  # Accumulated bit items
    count::Int64                # Records checked
    failed::Int64               # Failed checks
end

"""
    combine(accum1::Accum, accum2::Accum)

Combine accumulated values.
"""
function combine(accum1::Accum, accum2::Accum)::Accum
    # Ensure comment is nonempty if one input comment is nonempty.
    if accum1.comment == ""
        comment = accum2.comment
    else
        comment = accum1.comment
    end
    Accum(comment,
          accum1.acc | accum2.acc,
          accum1.count + accum2.count,
          accum1.failed + accum2.failed)
end

"""
    verify_ballot(er::Election_record, ballot::Submitted_ballot)

Verify one ballot.
"""
function verify_ballot(er::Election_record, ballot::Submitted_ballot)::Accum
    acc = 0                 # Accumulated bit items
    comment = ""            # Answer comment
    failed = false
    if !haskey(er.spoiled_ballots, ballot.code)
        for contest in ballot.contests
            for sel in contest.ballot_selections
                bits = is_selection_encryption_correct(er, sel)
                if bits != 0
                    name = ballot.object_id
                    comment = "Ballot $name has a bad selection encryption."
                    acc |= bits
                    failed = true
                end
            end
        end
    end
    Accum(comment, acc, 1, failed ? 1 : 0)
end

function is_selection_encryption_correct(er::Election_record,
                                         sel::Ballot_selection)::Int64
    is_selection_encryption_correct_d(er, sel) |
        is_selection_encryption_correct_e(er, sel) |
        is_selection_encryption_correct_f(er, sel)
end

function is_selection_encryption_correct_d(er::Election_record,
                                           sel::Ballot_selection)::Int64
    c = er.constants
    within_mod(sel.ciphertext.pad, c.q, c.p) &&
        within_mod(sel.ciphertext.data, c.q, c.p) ? 0 : D
end

function is_selection_encryption_correct_e(er::Election_record,
                                           sel::Ballot_selection)::Int64
    c = er.constants
    p = sel.proof
    within(p.proof_zero_response, c.q) &&
        within(p.proof_zero_challenge, c.q) &&
        within(p.proof_one_response, c.q) &&
        within(p.proof_one_challenge, c.q) ? 0 : E
end

function is_selection_encryption_correct_f(er::Election_record,
                                           sel::Ballot_selection)::Int64
    c = er.constants
    p = sel.proof
    v0 = p.proof_zero_response
    c0 = p.proof_zero_challenge
    v1 = p.proof_one_response
    c1 = p.proof_one_challenge
    alpha = sel.ciphertext.pad
    beta = sel.ciphertext.data
    a0 = mulpowmod(powermod(c.g, v0, c.p), alpha, c0, c.p)
    a1 = mulpowmod(powermod(c.g, v1, c.p), alpha, c1, c.p)
    k = er.context.elgamal_public_key
    b0 = mulpowmod(powermod(k, v0, c.p), beta, c0, c.p)
    w1 = mod(v1 - c1, c.q)
    b1 = mulpowmod(powermod(k, w1, c.p), beta, c1, c.p)
    mod(c0 + c1, c.q) ==
        eg_hash(c.q,
                "21",
                er.context.crypto_extended_base_hash,
                k,
                alpha,
                beta,
                a0,
                b0,
                a1,
                b1) ? 0 : F
end

end
