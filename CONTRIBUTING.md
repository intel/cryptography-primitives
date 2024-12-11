Intel® Cryptography Primitives Library Contribution Rules
=========================================================

## How to Contribute

We welcome community contributions to Intel® Cryptography Primitives Library!

If you have an idea how to improve the product:

 - Let us know via [GitHub* Issues](https://github.com/intel/ipp-crypto/issues).
 - Send your proposal directly via [pull request](https://github.com/intel/ipp-crypto/pulls).



## Intel® Cryptography Primitives Library repository scheme

Intel® Cryptography Primitives Library supports two repositories that are named as "Public Repository" and "Inner Repository". Privately hosted "Inner Repository" is required for extensive internal testing and experimental features development.

Existing automation guarantees regular synchronization of repositories.

<pre>
  +-------------+                     +------------+
  | Public Repo |        regular      | Inner Repo |
  | ----------- |    synchronization  |  --------  |       +----------+
  |    rev.1    | <------------------ |    rev.1   |       | internal |
  |    rev.2    |   bunch of changes  |    rev.2   |-----> | testing  |
  |    rev.3    |                     |    rev.3   |       +----------+
  +-------------+                     +------------+
</pre>

## License
Intel® Cryptography Primitives Library is licensed under the terms in LICENSE <https://github.com/intel/ipp-crypto/blob/develop/LICENSE>. By contributing to the project, you agree to the license and copyright terms therein and release your contribution under these terms.

## Developer Certification of Origin (DCO)
We encourage you to use Signed-off-by feature to comply with [Developer Certification of Origin (DCO)](https://developercertificate.org/).  
The name in the commit message Signed-off-by line and your email must match the change authorship information.  Make sure your .gitconfig is set up correctly so you can use `git commit -s` for signing your commits: 

`git config --global user.name "Kris Smith"`

`git config --global user.email Kris.Smith@company.com`

## Contribution Flow

- Contributor creates fork from develop, commits the changes into the created branch, opens a PR and requests a review.
- Contributor applies feedback provided by Intel® Cryptography Primitives Library repository maintainer in opened PR.
- Intel® Cryptography Primitives Library repository maintainer must ensure that the code is safe for internal execution, get code into inner repository and run private testing.
- Intel® Cryptography Primitives Library repository maintainer merges the changes "as is" from inner repository, when private testing is passed.
> **Note**
> Original PR is closed because merging PRs on the external GitHub repo isn't supported.

- Contributions will be available in the "Public repository", once the nearest cycle of synchronization from "Inner Repository" to "Public Repository" happens.

<pre>

  +-----------------+
  |   Public Repo   |
  |   -----------   |
  |   PR is open    |
  |       |         |
  |       |         |
  |       |         |                      +--------------------+
  |  Code Review    |                      |     Inner Repo     |
  |   has passed    |                      |      ---------     |
  |       |         |  PR is cherry-picked |    Heavy private   |
  |       |---------|----------------------|->     testing      |
  |       |         |   to "Inner Repo"    |          |         |
  |  PR is closed   |                      |          |         |
  +-----------------+                      |  Cherry-picked PR  |
                                           |     is merged      |
                                           |  to "Inner Repo"   |
                                           +--------------------+

</pre>

## Pull Request Checklist
Before sending your pull requests, ensure that:
 - Intel® Cryptography Primitives Library builds successfully with proposed changes using one of the compilers listed in [Build](./BUILD.md). Please specify which exact compiler was used.
 - Relevant documentation are added (for example CHANDELOG.md, README.md etc)
 - For new features make sure that
    - All new files are covered by copyrights.
    - All new internal functions are documented in comments.
    - Relevant examples are added(if required).

