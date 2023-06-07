## Branch strategy

The master branch is maintained at commercial quality. It only supports
COSE_Sign1. Changes against it must be very complete. Periodically a
new 1.x release is made from the master branch.

The "dev" branch is to become t_cose 2.0 when it gets to commercial
quality. It is to support COSE_Mac, COSE_Encrypt, multiple signers and
such.  PRs to it mainly need to not break the build and the CI.


## Tests and CI

Generally any PR should still have all these tests passing before it
will be merged.

### Basic tests

Running the standard make will produce `t_cose_test` for a particular
crypto library. It runs a thorough set of tests.

### CI tests

GitHub CI is used to build and test against several crypto libraries.

### tdv/b.sh tests

In the "tdv" repository there are some makes files and build scripts
that do some more thorough testing.  They are too large and take too
long to run to make them part of normal CI. Here's a few things they
do:

* Build with a fairly maximal set of compiler warning flags set (e.g.,
  -Wall)

* Build and test every combination of `#define` for configuration (this
  is what takes a long time)

* Build for use in a C++ program

* Measure and output code size


## PR Characteristics

I review PRs pretty thoroughly largely because I assume I am going to
have to provide support for them long term as I aim to make sure this
is high-quality, tested commercial code.  No one pays me for this and
there is no team or company behind this.

Here's a few notes on getting PRs merged:

* Only change what you need to. Don't beautify code that is not
  related to your change. Don't adjust tabs and spaces. Don't fix
  spelling mistakes or comment formatting that is not related to the
  change. This helps reduce merge conflicts and makes review
  easier. If you want to beautify and such, please do, but in
  separate PRs so intent is clear.

* Make sure all the tests mentioned above in Tests and CI are passing

* Target the right branch. It is fairly easy to change the target
  branch of a PR in GitHub.



## Makefile and project files

There are makefiles for both cmake and regular make. Both sets need to
be kept up to date and functioning.

The GitHub CI uses cmake.

There are several "Makefile"s for different crypto
libraries. Generally, a change to one means a change to the others
(though we can probably make that better with a little more work).


## Coding Style

QCBOR uses camelCase and t_cose follows [Arm's coding
guidelines](https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git/tree/docs/contributing/coding_guide.rst)
resulting in code with mixed styles. For better or worse, an Arm-style
version of UsefulBuf is created and used and so there is a duplicate
of UsefulBuf. The two are identical. They just have different names.


## Features and conditionality

The goal is for t_cose's use of #defines to be much simpler than most other libraries.

A couple of principles govern feature variation and conditional compiliation:

* #define is NOT required to enable features. All features are "on" by
   default.

* The internal function link dependency of t_cose is designed to work
  well with the compiler -dead_strip option so linked object code is
  minimized.

* Attempts to call t_cose APIs or use t_cose features which are not
  supported by the crypto library often result in an error code being
  returned and sometimes in a link error.

* The primary use of #defines is to disable features to reduce object
  code size for use cases that need small code size.

### Users of t_cose

Pretty much all users of t_cose do not need to be concerned with
#defines as they are not needed to enable features in the library. All
the features are already enabled.

Users may find that sometimes they get error codes indicating a
feature isn't supported. This will usually be because the underlying
crypto library they are linking against doesn't support the feature,
not because the feature needs to be enabled in t_cose.

Users may also find that sometimes they get a link error reporting an
undefined symbol. This will again usually be because the underlying
crypto library being linked against doesn't support the feature.

For example, t_cose works with several versions of MbedTLS older
versions of which don't support AES key wrap. You can use t_cose with
these older versions just fine as long as you don't call any t_cose
APIs or use any t_cose features that need key wrap. If you do, you'll
probably get a T_COSE_ERR_UNSUPPORTED_XX error.

If your use case needs small object code, then it may be time to make
use of T_COSE_DISABLE_XXXX #defines and recompile the t_cose library.
But it also might be that the minimized link dependency and
-dead_strip does everything you need too.


### Contributing to t_cose

If you are adding a feature to t_cose don't assume that a #define will
be needed and try pretty hard to avoid one.

Try to implement with minimal symbol/link dependency. One way to do
this is to create a new signer or recipient object just for the
feature. This might involve a new function in the crypto adaptor layer
for a new feature from the crypto library put to use. The new function
is only linked when the new feature is used.

The crypto layer has a facility for listing and discovering crypto
algorithms that are supported or not by a particular crypto
library. This facility is mostly used to know what to test, but not
exclusively.

If a feature can work in multiple modes or have multiple behaviors,
don't control that with a #define. Instead control that with an option
flag or with some API methods.  One bad thing about using a #define is
that in the case of a shared library everyone using the shared library
has to user the same mode.

Then in the end, the only reason to use a #ifdef should be to reduce
object code if there's no other way. Even then, the #ifdef shouldn't
make the code hard to read and shouldn't be complicated.





