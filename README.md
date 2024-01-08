## Github Utils
### How to use
This is a python script, so just run
```shell
python gh-utils.py <args>
```

### Requirements
The required python dependencies are indicated in the `requirements.txt` file, they can be installed with:
```shell
pip install -r requirements.txt
```

### Token
This script requires a Github token to query the API.
It expects to find one in the `GITHUB_TOKEN` environment variable.

The exact permissions needed on the token depends on what function you want to query,
but overall it's read-only permissions on the repository content, pull request, and organization teams.

### Commands
#### Pull Request
##### Team Files
List files edited in a PR which are owned by a given team.

```shell
python gh-utils.py pr --url <pr_url> team-files --team <team_name>
```

There is a `--link` or `-l` flag which prints links to those files instead of just their path.

##### Reviewers
List teams that own unreviewed files.

Note that this is not the same thing as still being requested for review, in case another team owns
the same files as you and has already reviewed.

```shell
python gh-utils.py pr --url <pr_url> reviewers
```

There is a `--minimal` or `-m` flag which instead only prints the minimal set of teams needed to review.
This is minimal in terms of number of teams.

This is convenient if you only need one review per owner, and codeowners are interlapping.
