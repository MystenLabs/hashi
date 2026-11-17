# Move Verification (CVLM)

# Setup

Move “specs” (rules and summaries) are written in Move.  Typically these will be in their own Move package, maybe named `spec` , which will have dependencies on the code being verified, and the Certora-provided `cvlm` and platform summary packages.

Here’s an example `Move.toml` file for a spec package for the [“Review Rating” example from the Sui documentation](https://docs.sui.io/guides/developer/app-examples/reviews-rating):

```toml
[package]
name = "spec"
edition = "2024.beta"

[dependencies]
reviews_rating = { local = "../sui/examples/move/reviews_rating" }
cvlm = { git = "https://github.com/Certora/cvl-move-proto.git", subdir = "cvlm", rev = "main" }
certora_sui_summaries = { git = "https://github.com/Certora/cvl-move-proto.git", subdir = "certora_sui_summaries",  rev = "main" }

[addresses]
spec = "0x0"
```

Note the three dependencies:

- `reviews_rating`: the code being verified with this spec
- `cvlm`: The “spec language” for Move projects.  This defines functions for defining rules, summaries, etc.  This is the interface between Move code and the Prover.
- `certora_sui_summaries`: Common summaries for Sui platform features.  Provides features such as storage, events, data structures, etc.

# Writing a Rule

Rules are defined with functions in Move code.  To identify a function as a rule, the module that defines the rule must also define a “manifest” function, called `cvlm_manifest` , which describes the rules (and summaries, etc.) present in that module.  For example, let’s define a simple “sanity” rule for one of the `reviews_rating` functions.  Here’s the spec file, `sources/rules.move`:

```rust
module spec::rules;

use reviews_rating::service::{ Service, ProofOfExperience };
use sui::clock::Clock;
use std::string::String;

use cvlm::asserts::cvlm_satisfy;
use cvlm::manifest::rule;

public fun cvlm_manifest() {
    rule(b"write_new_review_sanity");
}

public fun write_new_review_sanity(
    service: &mut Service,
    owner: address,
    content: String,
    overall_rate: u8,
    clock: &Clock,
    poe: ProofOfExperience,
    ctx: &mut TxContext,
) {
    service.write_new_review(owner, content, overall_rate, clock, poe, ctx);
    cvlm_satisfy_msg(true, b"Reached end of function");
}
```

Note that the `cvlm_manifest` function identifies `write_new_review_sanity` as a rule.  

When the rule is checked, all of its parameters will receive non-deterministic arguments of each type. 

Because this rule uses `cvlm_satisfy`, it is a “satisfy” rule which will find an execution of the code which satisfies the condition.  In this case we are just checking if the prover can simulate the execution of the whole method.  

Rules can, of course, also use `cvlm_assert` in the usual way, along with many other CVLM functions.  See the [CVLM sources](https://github.com/Certora/cvl-move-proto/tree/main/cvlm/sources) for more.

(Note: We’re defining a “sanity” rule in this example just for simplicity.  The Move Prover has a feature that automatically generates sanity rules for the public functions in a module; see the [`module_sanity`](https://github.com/Certora/cvl-move-proto/blob/44a7d10507b6f09ba1fec2e45b80ed4d55cf66e0/cvlm/sources/manifest.move#L48) function.)

# Checking the Spec

We can check this spec with the following command (run from the directory containing our `Move.toml` file):

```bash
certoraSuiProver.py --server production --prover_version "master"
```

This will build the spec package and send it to the prover.

To see additional logging that can help in initial setup of the spec, we can also enable “setup helper” logging:

```bash
certoraSuiProver.py --java_args "-Dverbose.setup.helpers" ...
```

This extra logging shows things like platform functions that are missing summaries, or uses of features that aren’t fully supported yet, and can be useful to help determine what needs to be summarized for the spec to work.

We can also restrict the run to only a subset of the rules defined in the spec, using the standard `--rule` , `--excludeRule`, `--method`, and `--excludeMethod` CLI parameters.

# Sanity Rules

The Move Prover can automatically generate “sanity” rules for a set of functions from the target contract, via the `target` and `target_sanity` entries in `cvlm_manifest` :

```rust
public fun cvlm_manifest() {
    target(@reviews_rating, b"dashboard", b"create_dashboard");
    target(@reviews_rating, b"dashboard", b"register_service");
    target(@reviews_rating, b"moderator", b"add_moderator");
    target(@reviews_rating, b"moderator", b"delete_moderator");
    target(@reviews_rating, b"review", b"upvote");
    target(@reviews_rating, b"service", b"create_service");
    target(@reviews_rating, b"service", b"write_new_review");
    target(@reviews_rating, b"service", b"write_new_review_without_poe");
    target(@reviews_rating, b"service", b"distribute_reward");
    target(@reviews_rating, b"service", b"top_up_reward");
    target(@reviews_rating, b"service", b"generate_proof_of_experience");
    target(@reviews_rating, b"service", b"remove_review");
    target(@reviews_rating, b"service", b"upvote");

    target_sanity();
}
```

The `target` lines register the public functions of the “Reviews Rating” package as “target functions.”  These can then be used for sanity rules, or for parametric rules (see below).  The `target_sanity` line asks the Prover to generate sanity rules for each of the target functions.  

As with the built-in sanity rules in the EVM prover, two rules will be generated for each target function: a “satisfy true” rule, which checks that we can model the execution of the function all the way to the end, and an “assert true” rule, which checks that all of the assertions the Prover adds to the code will pass.   See the [EVM Prover docs](https://docs.certora.com/en/latest/docs/cvl/builtin.html#how-sanity-is-checked) for more info.

# Parametric Rules

We can write rules that take target functions as arguments, also known as “parametric rules.”  This allows rules to assert properties that must hold for any call (or even a sequence of calls).  For example, let’s assert the invariant that a review’s score only increases:

```rust
public fun cvlm_manifest() {
    target(@reviews_rating, b"service", b"create_service");
    target(@reviews_rating, b"service", b"write_new_review");
    target(@reviews_rating, b"service", b"write_new_review_without_poe");
    target(@reviews_rating, b"service", b"distribute_reward");
    target(@reviews_rating, b"service", b"top_up_reward");
    target(@reviews_rating, b"service", b"generate_proof_of_experience");
    target(@reviews_rating, b"service", b"remove_review");
    target(@reviews_rating, b"service", b"upvote");

		invoker(b"invoke")    
    rule(b"score_only_increases")
}

native fun invoke(target: Function, id: ID);

public fun score_only_increases(service: &mut Service, review_id: ID, target: Function) {
    let initial_score = service.get_total_score(review_id);
    invoke(target, review_id);
    let final_score = service.get_total_score(review_id);
    cvlm_assert(final_score >= initial_score);
}
```

As we’ve seen before, the `target` lines name the functions that will be the targets of this spec module.  `invoker` names a function that we’ll use to invoke the target.  The invoker function must take a `Function` argument, and may take additional arguments for any values that the rule will pass explicitly to the target function.  The rule itself also takes a `Function` argument, which is used to select the particular target to be invoked.

As with the EVM prover, The Move Prover will generate separate sub-rules for each rule/target function permutation, and solve each separately. 

# Summaries

We can write summaries in Move as well.  For example, this loop from the reviews example is probably hard for the Prover to reason about:

```rust
/// Finds the index of a review in top_reviews
fun find_idx(service: &Service, total_score: u64): u64 {
    let mut i = service.top_reviews.length();
    while (0 < i) {
        let review_id = service.top_reviews[i - 1];
        if (service.get_total_score(review_id) > total_score) {
            break
        };
        i = i - 1;
    };
    i
}
```

We can replace this code with our own, using a summary function.  But first, our summary will need a way to access the `top_reviews` field of `Service` .  Fields are private to the defining module in Move, so we need to provide an accessor in the `service` module.  We also need a way to call the private `get_total_score` function.  So let’s add these to `service.move`:

```rust
#[test_only]
public fun top_reviews(service: &Service): vector<ID> {
    service.top_reviews
}
#[test_only]
public fun get_total_score_(service: &Service, review_id: ID): u64 {
    service.get_total_score(review_id)
}
```

Note that this is a change to the code that we’re verifying, but we mark it `test_only` so that it will not be available in production.  (This is why we typically build spec packages with the `--test` option.)

With that in place, we can add a summary to our spec package, in `sources/summaries.move`:

```rust
module spec::summaries;

use reviews_rating::service::Service;

use cvlm::manifest::summary;
use cvlm::nondet::nondet;
use cvlm::asserts::cvlm_assume;

public fun cvlm_manifest() {
    summary(b"find_idx_summary", @reviews_rating, b"service", b"find_idx");
}

#[test_only]
public fun find_idx_summary(service: &Service, total_score: u64): u64 {
    if (service.top_reviews().length() == 0) {
        return 0
    };
    let i = nondet<u64>();
    cvlm_assume(
        (i == 0 || service.get_total_score_(service.top_reviews()[i - 1]) > total_score) &&
        service.get_total_score_(service.top_reviews()[i]) <= total_score
    );
    i
}
```

In `cvlm_manifest`, we establish that `find_idx_summary` is a summary for `reviews_rating::service::find_idx`.  We mark `find_idx_summary` as “test-only,” giving it access to the test-only accessors we defined earlier.  In place of the original code’s loop, we use the `nondet` function plus `cvlm_assume` to ask the Prover to infer which index meets the criteria of the original loop. 

# Ghost State, Shadow Mappings, and Hash Functions

Additional advanced features are available via CVLM:

- Ghost state: provides “global” variables and mappings for the use of rules and summaries.
- Shadow mappings: allow advanced summaries that replace a Move `struct` definition with an alternate representation.
- Hash functions: generate unique `u256` values for given argument values.

Documentation for these can be found in [the `manifest` module in the CVLM repo](https://github.com/Certora/cvl-move-proto/blob/main/cvlm/sources/manifest.move).  Examples of usage can be found in the [Sui platform summaries](https://github.com/Certora/cvl-move-proto/tree/main/certora_sui_summaries/sources).