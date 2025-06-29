# git-overlay

Version control for gitignored files, by overlaying one repository over another.

## The Plan
Create a command-line app `git-overlay` that can initialize / clone a second repository into the .git directory, set up a remote for it, and provide functionality that can be integrated into git hooks, so that 
- when a commit it made, a commit is also made to overlaid repository, and that commit in the overlaid repository is then tagged with the associated commit in the base repo
- when checking out, all files in the repo that are currently managed by the overlay are removed, the overlay's associated commit is checkout out, and the new versions are copied over or maybe symlinked into the main working tree
- some more for synchronizing pushing and pulling of the base repo with the overlay

The cli should also have a `gitoverlay add` command, which stages files in the overlay, thereby preparing them to be auto committed when the git hook is called.

This add command should work similarly to `git add`, where it can be called on entire directories. In that case however it needs to understand which files are supposed to be managed by the overlay. Again, analogously to `git add` and `.gitignore` files, this command will respect `.overlayignore` files, specifying, with the same pattern syntax, which files should also be ignored by the overlay. The command also won't add (or at least issue a warning for) files that aren't gitignored by the base repo.

## Details

### Commit association

The overlay repository's commits are tagged with the commit hashes of the underlying commits in the base repo. If multiple commits in the base repo are made without changing any of the files managed by the overlay then the overlay commit has multiple tags pointing to it, one for each base commit.

### Commit Hook
Commit all changes staged in the overlay.
Still need to figure out some details, for where to append this commit.

### Post Checkout Hook

Git's post checkout hook receives as arguments
- the checked out commit
- the commit before the checkout
- whether this was a branch or a file checkout

For both commits the hook needs to figure out which commits in the overlay they are associated with. If there is no recorded association via tags yet (see [Commit association](#commit-association) then the hook has to trace backwards through the base repo's commit history until it either finds a root commit, or one that already has an association. It should then create the association for all passed through commits.
Details need to be worked out for when this process goes through a merge commit.

If the overlay commits associated to the two base commits are not the same then the hook has to first clean up the files from the first commit, and then create the files from the checkout one.

As the name suggests the hook runs *after* a successful checkout and there is no pre checkout hook.

This creates some sort of a problem, since 
    1. it is not possible to first clean up all the files managed by the overlay before the checkout to then only create the files of the new commit after the checkout
    2. it is not possible to interrupt the checkout if the overlay has unstaged / uncommitted changes that could lead to conflicts

The problem comes up if the checked out commit contains a file that, prior to checkout, was managed by the overlay.
The base repo, being completely oblivious to the overlay's existence, treats these file like any other gitignored file, meaning it simply overwrites it.
This means that the post checkout hook needs to
    1. explicitly check if after checkout the file is now managed by the base repo, and only delete it if it isn't
    2. Create some kind of extra file with the unstaged and uncommitted changes, and notify the user that these changes were left in the tree

Changes unstaged in the overlay, which are then overwritten by the base, however, can not be saved this way, as they will simply be overwritten by the checkout, and cannot not be retrieved from the overlay's index... Not sure what to do about that.


## Future ideas

### Orthogonal commits in the overlay
Suppose something changes about the system or environment that your overlay is intended for.
Maybe you change the path of some file that is reference by one of the files in your overlay.
Then you would need to update the overlay.
In particular you need to update *every overlay commit* in which that file exists, if you want to be able to use the base repo at each of those (associated) commits.
So really you want to create *a set of commits orthogonal to the ones that track the base*.

