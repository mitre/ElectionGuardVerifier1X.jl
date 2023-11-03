# 1. Parameter Validation

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Params

Ensure the constants are the standard ones.
"""
module Params

using SHA
using ..Datatypes
using ..Answers
using ..Utils: same
using ..Standard_constants
using ..Hash

export verify_params

const ver =
    parse(BigInt,
          "76322E3000000000000000000000000000000000000000000000000000000000",
          base = 16)

"1. Parameter Validation"
function verify_params(er::Election_record)::Answer
    acc = 0
    comment = "Standard parameters were found."
    count = 0
    failed = 0
    er_const = er.constants

    # Large prime (Item B)
    count += 1
    bits = er_const.p == constants.p ? 0 : B
    if bits != 0
        acc |= bits
        comment = "Large prime is not standard."
        failed += 1
    end

    # Small prime (Item C)
    count += 1
    bits = er_const.q == constants.q ? 0 : C
    if bits != 0
        acc |= bits
        comment = "Small prime is not standard."
        failed += 1
    end

    # Cofactor (Item D)
    count += 1
    bits = er_const.r == constants.r ? 0 : D
    if bits != 0
        acc |= bits
        comment = "Cofactor is not standard."
        failed += 1
    end

    # Generator (Item E)
    count += 1
    bits = er_const.g == constants.g ? 0 : E
    if bits != 0
        acc |= bits
        comment = "Generator is not standard."
        failed += 1
    end

    q = er_const.q
    er_ctx = er.context

    hash_p = eg_hash(q, ver, "00", er_const.p, q, er_const.g)
    manifest_hash = er_ctx.manifest_hash
    hash_m = eg_hash(q, hash_p, "01", manifest_hash)
    hash_q = eg_hash(q, hash_p, "02", hash_m,
                     er_ctx.number_of_guardians,
                     er_ctx.quorum)

    # Check manifest hash (Item I)
    count += 1
    bits = hash_q == er_ctx.crypto_base_hash ? 0 : I
    if bits != 0
        acc |= bits
        comment = "Election base hash is not correct."
        failed += 1
    end

    answer(1, bits2items(acc), "Parameter verification",
           comment, count, failed)
end

end
