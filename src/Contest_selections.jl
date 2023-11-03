# 10. Validation of Contest Selections with the Manifest

#=
Copyright (c) 2022 The MITRE Corporation

This program is free software: you can redistribute it and/or
modify it under the terms of the MIT License.
=#

module Contest_selections

using ..Datatypes
using ..Answers
using ..Parallel_mapreduce

export verify_contest_selections

"10. Validation of Contest Selections with the Manifest in the Tally"
function verify_contest_selections(er::Election_record,
                                  tally::Tally)::Answer
    verify_contest_selections(er, tally, true)
end

"13. Validation of Contest Selections with the Manifest in Spoiled Ballots"
function verify_contest_selections(er::Election_record,
                                  sp::Spoiled_ballot)::Answer
    tally = Tally(sp.tally_id, sp.name, sp.contests)
    verify_contest_selections(er, tally, false)
end

function verify_contest_selections(er::Election_record,
                                   tally::Tally,
                                   is_tally)::Answer
    acc = 0                     # Accumulated bit items
    # B means an extra contest is in the tally
    # C means an extra ballot selection is in the tally
    # D means a ballot selection is missing in the tally
    # E means a contest is missing in the tally
    count = 0                   # Records checked
    failed = 0
    step = 10
    if is_tally
        name = "Tally"
    else
        name = "Spoiled ballot " * tally.name
        step += STEP_DELTA
    end
    comment = "$name selections agree with the manifest."

    # See if every ballot selection in the manifest is in the tally
    # when the contest is in the tally.
    contests = er.manifest.contests
    tally_contests = tally.contests

    for (id, contest) in contests
        count += 1
        if haskey(tally_contests, id)
            tally_contest = tally_contests[id]
            for (sel_id, sel) in contest.ballot_selections
                failed_yet = false
                if !haskey(tally_contest.selections, sel_id)
                    comment =
                        "$name missing selection $sel_id in contest $id."
                    acc |= D
                    if !failed_yet
                        failed += 1
                        failed_yet = true
                    end
                end
            end
        end
    end

    if is_tally
        submitted_ballot_contents = all_contests(er)
        for ballot_contest in submitted_ballot_contents
            if !haskey(tally_contests, ballot_contest)
                comment = "$name has missing contest $ballot_contest."
                acc |= E
                failed += 1
            end
        end
    end

    # See if every contest selection in the tally is in the manifest.
    for (id, tally_contest) in tally_contests
        count += 1
        if !haskey(contests, id)
            comment = "$name has extra contest $id."
            acc |= B
            failed += 1
        else
            contest = contests[id]
            sels = contest.ballot_selections
            failed_yet = false
            for (sel_id, sel) in tally_contest.selections
                if !haskey(sels, sel_id)
                    if is_tally
                        comment =
                            "$name has extra selection $sel_id in contest $id."
                        acc |= C
                        if !failed_yet
                            failed += 1
                            failed_yet = true
                        end
                    end
                elseif sel.value != powermod(er.context.elgamal_public_key,
                                             BigInt(sel.tally), er.constants.p)
                        comment =
                            "$name has extra selection $sel_id with a bad tally.."
                        acc |= A
                        if !failed_yet
                            failed += 1
                            failed_yet = true
                        end
                end
            end
        end
    end

    answer(step, bits2items(acc),
           if is_tally
               "Validation of correct decryption of tallies"
           else
               "Validation of correct decryption of challenged ballots"
           end,
           comment, count, failed)
end

function set_of_contests(ballot::Submitted_ballot)::Set{String}
    set = Set{String}()
    for c in ballot.contests
        set = push!(set, c.object_id)
    end
    set
end

function all_contests(er::Election_record)::Set{String}
    pmapreduce(set_of_contests, union, er.submitted_ballots)
end

end
