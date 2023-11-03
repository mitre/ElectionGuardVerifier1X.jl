# A collection of functions that load ElectionGuard records.

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

"""
    Loader

The loader assumes the records are delivered using a standard
directory structure that is encoded here.  The structure is

- manifest.json: Data about the election
- constants.json: Constants used for ElGamal cryptography
- context.json: Election parameters
- guardians/*.json: Per guardian data
- submitted_ballots/*.json: Submitted ballots
- spoiled_ballots/*.json: Spoiled ballots (may be missing)
- encrypted_tally: Encrypted tally
- tally.json: The tally
"""
module Loader

import JSON

export load, load_constants

using ..Datatypes
using ..Record_version

"""
    load_json(path)

Load JSON from a file at the given path.
"""
function load_json(path)
    handle = open(path)
    try
        JSON.parse(handle)
    finally
        close(handle)
    end
end

function load_manifest_selection(dict)::Manifest_selection
    Manifest_selection(dict["object_id"])
end

function load_manifest_contest(dict)::Manifest_contest
    selections = Dict{String, Manifest_selection}()
    for val in map(load_manifest_selection, dict["ballot_selections"])
        selections[val.object_id] = val
    end
    votes_allowed = dict["votes_allowed"]
    Manifest_contest(dict["object_id"],
                     votes_allowed,
                     selections)
end

function load_manifest(path)::Manifest
    dict = load_json(path)
    contests = Dict{String, Manifest_contest}()
    for val in map(load_manifest_contest, dict["contests"])
        contests[val.object_id] = val
    end
    Manifest(dict["election_scope_id"],
             dict["spec_version"],
             dict["start_date"],
             dict["end_date"],
             contests)
end

"Load ElGamal constants."
function load_constants(path)::Constants
    dict = load_json(path)
    Constants(load_bigint(dict["large_prime"]),
              load_bigint(dict["small_prime"]),
              load_bigint(dict["cofactor"]),
              load_bigint(dict["generator"]))
end

"Load a BigInt."
function load_bigint(str)
    parse(BigInt, str, base = 16)
end

"Load a configuration"
function load_configuration(dict)::Configuration
    Configuration(dict["allow_overvotes"],
                  dict["max_votes"])
end

"""
    load_context(path)

Load an election context.
"""
function load_context(path)
    dict = load_json(path)
    Context(load_bigint(dict["manifest_hash"]),
            load_bigint(dict["commitment_hash"]),
            load_bigint(dict["crypto_base_hash"]),
            load_bigint(dict["crypto_extended_base_hash"]),
            load_bigint(dict["elgamal_public_key"]),
            dict["number_of_guardians"],
            dict["quorum"],
            load_configuration(dict["configuration"]))
end

function load_proof(dict)
    Schnorr_proof(dict["usage"],
                  load_bigint(dict["public_key"]),
                  load_bigint(dict["commitment"]),
                  load_bigint(dict["challenge"]),
                  load_bigint(dict["response"]))
end

function load_guardian(path)
    dict = load_json(path)
    Guardian(dict["guardian_id"],
             load_bigint(dict["key"]),
             map(load_bigint, dict["coefficient_commitments"]),
             map(load_proof, dict["coefficient_proofs"]))
end

function load_guardians(path)
    paths = readdir(path)
    map(file -> load_guardian(joinpath(path, file)), paths)
end

function load_ciphertext(dict)
    Ciphertext(load_bigint(dict["pad"]),
               load_bigint(dict["data"]))
end

function load_data_ciphertext(dict)
    Data_ciphertext(load_bigint(dict["pad"]),
                    load_bigint(dict["data"]),
                    load_bigint(dict["mac"]))
end

function load_disjuctive_proof(dict)
    Disjunctive_proof(load_bigint(dict["challenge"]),
                      load_bigint(dict["proof_zero_pad"]),
                      load_bigint(dict["proof_zero_data"]),
                      load_bigint(dict["proof_zero_challenge"]),
                      load_bigint(dict["proof_zero_response"]),
                      load_bigint(dict["proof_one_pad"]),
                      load_bigint(dict["proof_one_data"]),
                      load_bigint(dict["proof_one_challenge"]),
                      load_bigint(dict["proof_one_response"]))
end

function load_ballot_selection(dict)
    Ballot_selection(dict["object_id"],
                     load_bigint(dict["crypto_hash"]),
                     load_disjuctive_proof(dict["proof"]),
                     load_ciphertext(dict["ciphertext"]),
                     get(dict, "extended_data", nothing))
end

function load_integer_proof(item)
    if item isa Int64
        item
    else
        Zero_knowledge_proof(load_bigint(item["challenge"]),
                             load_bigint(item["response"]))
    end
end

function load_integer_proofs(array)
    map(load_integer_proof, array)
end

function load_ranged_proof(dict)
    Ranged_proof(load_bigint(dict["challenge"]),
                 map(load_integer_proofs, dict["proofs"]),
                 dict["range_limit"])
end

function load_contest_proof(dict)
    if dict == nothing
        nothing
    else
        load_ranged_proof(dict)
    end
end

function load_contest(dict)
    Contest(dict["object_id"],
            load_bigint(dict["crypto_hash"]),
            map(load_ballot_selection, dict["ballot_selections"]),
            load_contest_proof(dict["proof"]),
            load_ciphertext(dict["ciphertext_accumulation"]))
end

function load_submitted_ballot(path)
    dict = load_json(path)
    Submitted_ballot(dict["object_id"],
                     dict["code"],
                     map(load_contest, dict["contests"]))
end

function load_submitted_ballots(path)
    paths = readdir(path)
    map(file -> load_submitted_ballot(joinpath(path, file)), paths)
end

function load_encrypted_tally_selection(dict)
    Encrypted_tally_selection(dict["object_id"],
                              load_ciphertext(dict["ciphertext"]))
end

function load_encrypted_tally_contest(dict)
    selections = Dict{String, Encrypted_tally_selection}()
    for (_, val) in dict["selections"] # Note key not used
        selections[val["object_id"]] = load_encrypted_tally_selection(val)
    end
    Encrypted_tally_contest(dict["object_id"],
                            selections)
end

function load_encrypted_tally(path)
    dict = load_json(path)
    contests = Dict{String, Encrypted_tally_contest}()
    for (_, val) in dict["contests"] # Note key not used
        contests[val["object_id"]] = load_encrypted_tally_contest(val)
    end
    Encrypted_tally(dict["tally_id"],
                    dict["name"],
                    contests)
end

function load_chaum_pedersen_proof(dict)
    if dict === nothing
        nothing
    else
        Chaum_Pedersen_proof(load_bigint(dict["pad"]),
                             load_bigint(dict["data"]),
                             load_bigint(dict["challenge"]),
                             load_bigint(dict["response"]))
    end
end

function load_tally_selection(dict)
    Tally_selection(dict["object_id"],
                    dict["tally"],
                    load_bigint(dict["value"]),
                    load_chaum_pedersen_proof(dict["proof"]))
end

function load_tally_selections(dict)
    selections = Dict{String, Tally_selection}()
    for (_, val) in dict        # Note key not used
        selections[val["object_id"]] = load_tally_selection(val)
    end
    selections
end

function load_tally_contest(dict)
    Tally_contest(dict["object_id"],
                  load_tally_selections(dict["selections"]))
end

function load_tally_contests(dict)
    contests = Dict{String, Tally_contest}()
    for (_, val) in dict        # Note key not used
        contests[val["object_id"]] = load_tally_contest(val)
    end
    contests
end

function load_tally(path)
    dict = load_json(path)
    Tally(dict["tally_id"],
          dict["name"],
          load_tally_contests(dict["contests"]))
end

function load_spoiled_ballot(path)
    dict = load_json(path)
    Spoiled_ballot(dict["tally_id"],
                   dict["name"],
                   load_tally_contests(dict["contests"]))
end

function load_spoiled_ballots(path)
    spsv = Vector{Spoiled_ballot}()
    if isdir(path)
        paths = readdir(path)
        spsv = map(file -> load_spoiled_ballot(joinpath(path, file)), paths)
    end
    sps = Dict{String, Spoiled_ballot}()
    for sp in spsv
        sps[sp.name] = sp
    end
    sps
end

"""
    load_election_record(path::AbstractString)::Election_record

Load election records in the given directory.
"""
function load_election_record(path::AbstractString)::Election_record
    path = realpath(expanduser(path))
    manifest = load_manifest(joinpath(path, "manifest.json"))
    election_id = manifest.election_scope_id
    println("Loading $election_id.")
    check_record_version(manifest)
    constants = load_constants(joinpath(path, "constants.json"))
    context = load_context(joinpath(path, "context.json"))
    guardians = load_guardians(joinpath(path, "guardians"))
    submitted_ballots =
        load_submitted_ballots(joinpath(path, "submitted_ballots"))
    spoiled_ballots =
        load_spoiled_ballots(joinpath(path, "spoiled_ballots"))
    encrypted_tally =
        load_encrypted_tally(joinpath(path, "encrypted_tally.json"))
    tally = load_tally(joinpath(path, "tally.json"))
    Election_record(manifest,
                    constants,
                    context,
                    guardians,
                    submitted_ballots,
                    spoiled_ballots,
                    encrypted_tally,
                    tally)
end

"""
    load(path::AbstractString)::Election_record

Load election records in the given directory.  On error, print load error
message before crashing.
"""
function load(path::AbstractString)::Election_record
    try
        load_election_record(path)
    catch e
        println("Error loading the election record at $path")
	throw(e)
    end
end

end
