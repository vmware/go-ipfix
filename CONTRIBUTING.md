
# Contributing to go-ipfix

The go-ipfix project team welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).


## GitHub Contribution Workflow

Developers work in their own forked copy of the repository and when ready,
submit pull requests to have their changes considered and merged into the
project's repository.

1. Fork your own copy of the repository to your GitHub account by clicking on
   `Fork` button on [go-ipfix GitHub repository](https://github.com/vmware/go-ipfix).
2. Clone the forked repository on your local setup.
    ```
    git clone https://github.com/$user/go-ipfix
    ```
    Add a remote upstream to track upstream go-ipfix repository.
    ```
    git remote add upstream https://github.com/vmware/go-ipfix
    ```
    Never push to upstream main
    ```
    git remote set-url --push upstream no_push
    ```
3. Create a topic branch.
    ```
    git checkout -b branchName
    ```
4. Make changes and commit it locally.
    ```
    git add <modifiedFile>
    git commit
    ```
5. Update the "Unreleased" section of the [CHANGELOG](CHANGELOG.md) for any
   significant change that impacts users.
6. Keeping branch in sync with upstream.
    ```
    git checkout branchName
    git fetch upstream
    git rebase upstream/main
    ```
7. Push local branch to your forked repository.
    ```
    git push -f $remoteBranchName branchName
    ```
8. Create a Pull request on GitHub.
   Visit your fork at `https://github.com/vmware/go-ipfix` and click
   `Compare & Pull Request` button next to your `remoteBranchName` branch.

### Getting reviewers

Once you have opened a Pull Request (PR), reviewers will be assigned to your
PR and they may provide review comments which you need to address.
Commit changes made in response to review comments to the same branch on your
fork. Once a PR is ready to merge, squash any *fix review feedback, typo*
and *merged* sorts of commits.

To make it easier for reviewers to review your PR, consider the following:
1. Follow the golang [coding conventions](https://github.com/golang/go/wiki/CodeReviewComments)
2. Follow [git commit](https://chris.beams.io/posts/git-commit/) guidelines.
3. Follow [logging](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-instrumentation/logging.md) guidelines.

## Reporting Bugs and Creating Issues

When opening a new issue, try to roughly follow the commit message format conventions above.
