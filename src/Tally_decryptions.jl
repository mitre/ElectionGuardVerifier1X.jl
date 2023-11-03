# 9. Validation of Correct Decryption of Tallies

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Tally_decryptions

import Printf                   # For debugging the 9C hash
using ..Datatypes
using ..Answers
using ..Utils
using ..Hash
using ..Parallel_mapreduce

export verify_tally_decryptions

const DEBUG_HASH = false

"9. Validation of Correctness of Tally Decryptions"
function verify_tally_decryptions(er::Election_record,
                                  tally::Tally)::Answer
    acc = 0                     # Accumulated item bits
    count = 0                   # Records checked
    failed = 0
    # for each contest
    for (_, c) in tally.contests
        # for each selection in contest
        if !haskey(er.encrypted_tally.contests, c.object_id)
            count += 1
            failed += 1
            acc |= C
        else
            ec = er.encrypted_tally.contests[c.object_id]
            for (_, sel) in c.selections
                count += 1
                if !haskey(ec.selections, sel.object_id)
                    failed += 1
                    acc |= C
                else
                    esel = ec.selections[sel.object_id]
                    bits = are_tally_decryptions_correct(er,
                                                         sel,
                                                         esel.ciphertext)
                    if bits != 0
                        failed += 1
                        acc |= bits
                    end
                end
            end
        end
    end
    step = 9
    name = "Tally"
    if failed == 0
        comment = "$name decryptions are correct."
    else
        comment = "$name decryptions are incorrect."
    end
    answer(step, bits2items(acc),
           "Validation of correct decryption of tallies",
           comment, count, failed)
end

"12. Validation of Correctness of Decryptions for Spoiled Ballots"
function verify_tally_decryptions(er::Election_record,
                                  sp::Spoiled_ballot)::Answer
    acc = 0                     # Accumulated item bits
    count = 0                   # Records checked
    failed = 0
    sub = get_submitted(er.submitted_ballots, sp.name)
    if sub == nothing
        count += 1
        failed += 1
        acc |= C
    else
        # for each contest
        for c in sub.contests
            # for each selection in contest
            if !haskey(sp.contests, c.object_id)
                count += 1
                failed += 1
                acc |= C
            else
                ec = sp.contests[c.object_id]
                for sel in c.ballot_selections
                    count += 1
                    if !haskey(ec.selections, sel.object_id)
                        failed += 1
                        acc |= C
                    else
                        esel = ec.selections[sel.object_id]
                        bits = are_tally_decryptions_correct(er,
                                                             esel,
                                                             sel.ciphertext)
                        if bits != 0
                            failed += 1
                            acc |= bits
                        end
                    end
                end
            end
        end
    end
    step = 9
    step += STEP_DELTA
    name = "Spoiled ballot " * sp.name
    if failed == 0
        comment = "$name decryptions are correct."
    else
        comment = "$name decryptions are incorrect."
    end
    answer(step, bits2items(acc),
           "Validation of correctness of decryptions of challenged ballots",
           comment, count, failed)
end

function get_submitted(ballots::Vector{Submitted_ballot},
                       name::String)::Union{Submitted_ballot, Nothing}
    pmapreduce(sp -> sp.code == name ? sp : nothing,
               (a, b) -> a == nothing ? b : a,
               ballots)
end

function are_tally_decryptions_correct(er::Election_record,
                                       sel::Tally_selection,
                                       cipher::Ciphertext)::Int64
    are_tally_decryptions_correct_a(er, sel) |
        are_tally_decryptions_correct_c(er, sel, cipher)
end

# v is in Z_q
function are_tally_decryptions_correct_a(er::Election_record,
                                         sel::Tally_selection)::Int64
    c = er.constants
    within(sel.proof.response, c.p) ? 0 : A
end

# v == hash("30", Qbar, K, A, B, a, b, M) [With special hash algorithm]
function are_tally_decryptions_correct_c(er::Election_record,
                                         sel::Tally_selection,
                                         cipher::Ciphertext)::Int64
    c = er.constants
    ctx = er.context

    m = mulpowmod(cipher.data, sel.value, BigInt(-1), c.p)
    k = ctx.elgamal_public_key
    a = mulpowmod(powermod(c.g, sel.proof.response, c.p),
                  k, sel.proof.challenge,  c.p)
    b = mulpowmod(powermod(cipher.pad, sel.proof.response, c.p),
                  m, sel.proof.challenge,  c.p)

    # hash the prefix
    hash = eg_hash(c.q, "30")
    for x in [ctx.crypto_extended_base_hash,
                k,
                cipher.pad,
                cipher.data,
                a,
                b,
                m]
        # and then hash each term separately
        hash = eg_hash(c.q, hash, x)
    end
    # previous method
    # hash = eg_hash(c.q,
    #               "30",
    #                ctx.crypto_extended_base_hash,
    #                k,
    #                cipher.pad,
    #                cipher.data,
    #                a,
    #                b,
    #                m)

    if DEBUG_HASH
        Printf.@printf("sel.object_id = %s\n", sel.object_id)
        Printf.@printf("m = %2X\n", m)
        Printf.@printf("a = %2X\n", a)
        Printf.@printf("b = %2X\n", b)
        Printf.@printf("A = %2X\n", cipher.pad)
        Printf.@printf("B = %2X\n", cipher.data)
        Printf.@printf("computed hash = %2X\n", hash)
        Printf.@printf("expected hash = %2X\n\n", sel.proof.challenge)
    end

    sel.proof.challenge == hash ? 0 : C
end

end # Tally_decryptions module
