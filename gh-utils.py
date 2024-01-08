# For a given PR:
# - List codeowner teams which own unreviewed files
# - List files owned by a given team
# - Find the minimal set of codeowner teams needed to have reviews on all files
#
# Some caveats:
# - Github doesn't provide a way to get the list of teams which have already reviewed a PR.
#   As a workaround, get the list of all codeowners and remove the ones which have already reviewed the PR.
# - Github doesn't provide a way to get all teams of a user with the REST API.
# - Github doesn't provide an API around codeowners, so we download the file and use a library to parse it.


import argparse
import os
import re
import sys
from collections import defaultdict
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from codeowners import CodeOwners, OwnerTuple
from github import Auth, Github
from github.ContentFile import ContentFile
from github.NamedUser import NamedUser
from github.PullRequest import PullRequest
from github.Repository import Repository
from github.Team import Team


def _get_codeowners(repo: Repository, pull_base: str) -> CodeOwners:
    """Returns the codeowners of the given repo, on the given branch"""

    # https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners#codeowners-file-location
    # To use a CODEOWNERS file, create a new file called CODEOWNERS in the .github/, root, or docs/ directory
    # of the repository, in the branch where you'd like to add the code owners.
    # If CODEOWNERS files exist in more than one of those locations, GitHub will search for them in that order
    # and use the first one it finds.
    CODEOWNER_PATHS = [".github", ".", "docs"]
    CODEOWNER_FILE_NAME = "CODEOWNERS"

    for codeowner_path in CODEOWNER_PATHS:
        try:
            # https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners#codeowners-file-location
            # For code owners to receive review requests, the CODEOWNERS file must be on the base branch
            # of the pull request
            ret = repo.get_contents(f"{codeowner_path}/{CODEOWNER_FILE_NAME}", pull_base)
            if isinstance(ret, ContentFile):
                # return type is a list if the path is a directory
                codeowners_raw = ret.decoded_content
                codeowners = str(codeowners_raw, "utf-8")
                return CodeOwners(codeowners)
        except Exception:
            pass

    raise Exception("No CODEOWNERS file found")


# returns the list of still requested reviewers
def _get_pull_requested_reviews(pull: PullRequest) -> Tuple[List[NamedUser], List[Team]]:
    """Returns the list of still requested reviewers"""
    requested_users, requested_teams = pull.get_review_requests()
    return list(requested_users), list(requested_teams)


def _get_pull_files_and_owners(pull: PullRequest, codeowners: CodeOwners) -> Dict[str, Set[OwnerTuple]]:
    """Returns the files edited by the given PR, along with their owners"""
    files = pull.get_files()

    files_and_owners = {}
    for file in files:
        files_and_owners[file.filename] = set(codeowners.of(file.filename))

    return files_and_owners


def _get_files_owners(files_and_owners: Dict[str, Set[OwnerTuple]]) -> Set[OwnerTuple]:
    """Returns the codeowners of the given files"""
    owners = set()
    for owners_list in files_and_owners.values():
        owners.update(owners_list)
    return owners


def _get_already_reviewed(
    all_owners: Set[OwnerTuple], requested_review_user: List[NamedUser], requested_review_teams: List[Team]
) -> Set[OwnerTuple]:
    """
    Returns the owners which have already reviewed the PR.

    Github doesn't provide this information directly, so we find codeowners of all edited files,
    and remove the ones which are still requested for review.
    """
    already_reviewed = set(all_owners)

    for user in requested_review_user:
        already_reviewed.discard(("USERNAME", user.login))
        if user.email is not None:
            already_reviewed.discard(("EMAIL", user.email))

    for team in requested_review_teams:
        team_name = f"@{team.organization.login}/{team.name}"
        already_reviewed.discard(("TEAM", team_name))

    return already_reviewed


def _get_unreviewed_files(
    files_and_owners: Dict[str, Set[OwnerTuple]], already_reviewed: Set[OwnerTuple]
) -> Dict[str, Set[OwnerTuple]]:
    """Returns the files which have not been reviewed yet, along with their owners"""
    unreviewed_files = {}
    for file, owners in files_and_owners.items():
        if owners.isdisjoint(already_reviewed):
            unreviewed_files[file] = owners

    return unreviewed_files


def _get_unreviewed_file_owners(pull: PullRequest, codeowners: CodeOwners):
    """Returns the files which have not been reviewed yet, along with their owners"""
    all_files_and_owners = _get_pull_files_and_owners(pull, codeowners)
    all_owners = _get_files_owners(all_files_and_owners)
    requested_review_user, requested_review_teams = _get_pull_requested_reviews(pull)
    already_reviewed = _get_already_reviewed(all_owners, requested_review_user, requested_review_teams)
    return _get_unreviewed_files(all_files_and_owners, already_reviewed)


def _get_team_files(files_and_owners: Dict[str, Set[OwnerTuple]], team: str) -> Set[str]:
    """Returns the files owned by a given team"""
    team_files = set()
    for file, owners in files_and_owners.items():
        if ("TEAM", "@" + team) in owners:
            team_files.add(file)

    return team_files


def _get_minimal_reviewers(unreviewed_files: Dict[str, Set[OwnerTuple]]) -> Set[OwnerTuple]:
    """
    Find the minimal set of reviewers needed to have reviews on all files.

    This is a [set cover problem](https://en.wikipedia.org/wiki/Set_cover_problem) and is NP-hard,
    so we use a greedy algorithm instead to get an approximation.
    """

    reviewers = set()

    # find files with a single owner
    for owners in unreviewed_files.values():
        if len(owners) == 1:
            reviewers.update(owners)

    owner_to_files: defaultdict[OwnerTuple, Set[str]] = defaultdict(set)
    for filename, owners in unreviewed_files.items():
        if not reviewers.isdisjoint(owners):
            # file is already covered
            continue
        for owner in owners:
            owner_to_files[owner].add(filename)

    while owner_to_files:
        # find the owner with the most files
        owner, files = max(owner_to_files.items(), key=lambda x: len(x[1]))
        if len(files) == 0:
            break

        # add it to the reviewers, and remove its files from the unreviewed files
        reviewers.add(owner)
        del owner_to_files[owner]
        # also remove those files from the other owners
        for filename in files:
            for owner in unreviewed_files[filename]:
                if owner in owner_to_files:
                    owner_to_files[owner].discard(filename)
                    if len(owner_to_files[owner]) == 0:
                        del owner_to_files[owner]

    return reviewers


def _pr_url(url: str) -> Tuple[str, int]:
    """Returns the repo name and the PR number from a PR URL"""
    parsed = urlparse(url)
    PATH_PATTERN = "/([^/]+/[^/]+)/pull/([0-9]+)(/.*)?"
    match = re.match(PATH_PATTERN, parsed.path)
    if not match:
        raise ValueError(f"Invalid PR url: {url}")
    return match.group(1), int(match.group(2))


def _get_file_url(html_url: str, branch: str, filepath: str) -> str:
    """Returns the file url on github"""
    return f"{html_url}/blob/{branch}/{filepath}"


def _command_get_needed_reviewers(gh: Github, ns: argparse.Namespace):
    """List codeowners owning unreviewed files in a given PR"""
    repo_name, pr_number = ns.url
    repo = gh.get_repo(repo_name)
    pull = repo.get_pull(pr_number)
    codeowners = _get_codeowners(repo, pull.base.ref)

    unreviewed_files = _get_unreviewed_file_owners(pull, codeowners)
    if ns.minimal:
        reviewers = _get_minimal_reviewers(unreviewed_files)
    else:
        reviewers = _get_files_owners(unreviewed_files)

    for reviewer in reviewers:
        print(reviewer)


def _command_get_team_files(gh: Github, ns: argparse.Namespace):
    """List files owned by a team in a given PR"""
    repo_name, pr_number = ns.url
    repo = gh.get_repo(repo_name)
    pull = repo.get_pull(pr_number)
    repo_html_url = repo.html_url
    codeowners = _get_codeowners(repo, pull.base.ref)

    files_and_owners = _get_pull_files_and_owners(pull, codeowners)

    files = _get_team_files(files_and_owners, ns.team)
    for filename in files:
        if ns.link:
            print(_get_file_url(repo_html_url, pull.head.ref, filename))
        else:
            print(filename)


def _get_arg_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser"""
    parser = argparse.ArgumentParser(description="Get information from GitHub.")

    subparsers = parser.add_subparsers(required=True, help="pick a subcommand")

    parser_pr = subparsers.add_parser("pull-request", aliases=["pr"], help="pull request related subcommands")
    parser_pr.add_argument("-u", "--url", type=_pr_url, required=True, help="the pull request url")

    subparser_pr = parser_pr.add_subparsers(required=True, help="pick a subcommand")

    subparser_pr_team_files = subparser_pr.add_parser("team-files", aliases=["tf"], help="list files owned by a team")
    subparser_pr_team_files.add_argument("-t", "--team", required=True, help="the github team name")
    subparser_pr_team_files.add_argument("-l", "--link", action="store_true", help="display file links")
    subparser_pr_team_files.set_defaults(func=_command_get_team_files)

    subparser_pr_reviewers = subparser_pr.add_parser(
        "reviewers", aliases=["r"], help="list codeowners owning unreviewed files"
    )
    subparser_pr_reviewers.set_defaults(func=_command_get_needed_reviewers)
    subparser_pr_reviewers.add_argument("-m", "--minimal", action="store_true", help="display minimal reviewers")

    return parser


if __name__ == "__main__":
    parser = _get_arg_parser()
    ns = parser.parse_args()
    if not ns.func:
        print("Unexpected error while parsing arguments", file=sys.stderr)
        print(file=sys.stderr)
        parser.print_usage(sys.stderr)
        sys.exit(1)

    # Get GitHub token from environment variable
    if "GITHUB_TOKEN" not in os.environ:
        raise Exception("GITHUB_TOKEN environment variable not set")
    GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]

    auth = Auth.Token(GITHUB_TOKEN)
    gh = Github(auth=auth)

    ns.func(gh, ns)

    gh.close()
