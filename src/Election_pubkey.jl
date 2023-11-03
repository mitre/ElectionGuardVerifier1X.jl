# 3. Election Public-Key Validation

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Election_pubkey

using ..Datatypes
using ..Answers
using ..Utils

export verify_election_pubkey

" 3. Election Public-Key Validation"
function verify_election_pubkey(er::Election_record)::Answer
    p = er.constants.p
    bits = 0

    # K_i is in Z^r_p and K_i != 1 mod p
    for g in er.guardians
        k = g.key
        if !within(k, p) || mod(k, p) == BigInt(1)
            bits |= A
        end
    end

    # K = prod(K_i) mod p and K != 1 mod p (Item B)
    keys = map(g -> g.key, er.guardians)
    if mod(prod(keys), p) != er.context.elgamal_public_key ||
        mod(er.context.elgamal_public_key, p) == BigInt(1)
        bits |= B
    end

    if bits == 0
        answer(3, "", "Election public-key validation",
               "Election pubkey is valid.", 1, 0)
    else
        answer(3, bits2items(bits), "Election public-key validation",
               "Election pubkey is invalid.", 1, 1)
    end
end

end
