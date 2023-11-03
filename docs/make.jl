# ElectionGuardVerifier1X.jl documentation
#
# Build with:
#
# julia --project make.jl

using Documenter, ElectionGuardVerifier1X
import Documenter.Remotes.GitLab  # Temporary

makedocs(
    sitename = "ElectionGuard Verifier",
    authors = "John D. Ramsdell and Moses D. Liskov",
    format = Documenter.HTML(prettyurls = false),
    # repo definition is temporary until the move to GitHub
    repo = GitLab("gitlab.mitre.org",
                  "electionguard",
                  "mitre-electionguard-verifier-1x"),

    pages = [
        "Home" => "index.md",
        "installation.md",
        "usage.md",
        "results.md",
        "development.md"
    ]
)
