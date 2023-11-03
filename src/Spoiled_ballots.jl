# 13. Validation of Correct Decryption of Spoiled Ballots

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Spoiled_ballots

using ..Datatypes
using ..Answers
using ..Tally_decryptions
using ..Contest_selections

export verify_spoiled_ballots

function print_push!(as::Vector{Answer}, a::Answer)
    println(a)
    push!(as, a)
end

"""
12 and 13.  Validation of Correctness of Decryptions and
Correct Decryption of Challenged Ballots
and 
"""
function verify_spoiled_ballots(er::Election_record)::Vector{Answer}
    as = Vector{Answer}()
    for (_, ballot) in er.spoiled_ballots
        print_push!(as, Tally_decryptions.
            verify_tally_decryptions(er, ballot))
        print_push!(as, Contest_selections.
            verify_contest_selections(er, ballot))
    end
    as
end

end
