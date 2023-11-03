# 4. Extended Base Hash Validation

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Extended_base_hash

using ..Datatypes
using ..Answers
using ..Hash

export verify_extended_base_hash

" 4. Extended Base Hase Validation"
function verify_extended_base_hash(er::Election_record)::Answer
    hash = eg_hash(er.constants.q,
                   er.context.crypto_base_hash,
                   "12",
                   er.context.elgamal_public_key,
                   er.context.commitment_hash)

    if hash == er.context.crypto_extended_base_hash
        bits = 0
    else
        bits = B
    end

    if bits == 0
        answer(4, "", "Extended base hash validation",
               "Extended base hash is valid.", 1, 0)
    else
        answer(4, bits2items(bits), "Extended base hash validation",
               "Extended base hash is not valid.", 1, 1)
    end
end

end
