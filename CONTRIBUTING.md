# Contributing

## Pull request workflow

1. Create a branch from the latest `main` for the change.
2. Make the change and run the relevant checks. The project does not currently have automated CI checks, so review the diff and validate the affected workflows manually.
3. Push the branch and open a pull request targeting `main`. Use a clear title and describe the change, its impact, and the validation performed.
4. Review the complete diff and any available checks before merging. GitHub does not allow authors to approve their own pull requests. If branch protection requires an independent approval, ask another contributor to review; otherwise, the author can merge after completing their own review.
5. Delete the feature branch after the pull request is merged, if it is no longer needed.

The GitHub CLI can be used for common operations:

```bash
gh auth status
git push -u origin <branch-name>
gh pr create --base main --head <branch-name>
gh pr view --web
gh pr checks
gh pr diff
```

## Changes that do not require a release

Documentation updates and other changes that do not affect the application can still follow the pull request workflow above. Create a branch, open a pull request targeting `main`, review the diff, and merge it when ready.

After merging, do not create a version tag or GitHub Release just for these changes. They will be included in the next release that is published. If a change is small and the repository's contribution rules allow direct commits to `main`, a pull request may be optional, but the diff should still be reviewed.

## Releases and version tags

Use Semantic Versioning tags prefixed with `v`, such as `v0.1.0`. While the major version is `0`, the project is in initial development and its public interfaces may change.

Create a release only after its pull request has been merged into `main`:

```bash
git switch main
git pull --ff-only origin main
git tag --list 'v*' --sort=-v:refname
```

Choose the next version based on the changes since the previous release. Create and push an annotated tag on the intended `main` commit, then create the GitHub Release:

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
gh release create vX.Y.Z --generate-notes
```

Do not move or reuse a published version tag. A documentation-only change does not by itself require a new release or a version bump; create a new tag when you are ready to publish another release.
