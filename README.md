## Introduction

This repository contains an implementation of a lattice-based one-time signature scheme (similar to the one published by [Lyubashevsky and Micciancio](https://eprint.iacr.org/2013/746.pdf)), and an extension to [Boneh and Kim](https://github.com/geometry-labs/rsis/blob/dev-end-of-january/lmsigs/agg_ots/agg_ots.py) style signature aggregation. An upcoming release will include prototypes of our novel one-time adaptor signature scheme.

## Explanatory resources
The "Techniques for efficient post-quantum finance" finance series contains several articles that go into detail about how these schemes work.

+ For more information about the one-time signature scheme (`lm_one_times_sigs`) see this writeup: [https://www.theqrl.org/blog/techniques-for-efficient-post-quantum-finance-part-1-digital-signatures/](https://www.theqrl.org/blog/techniques-for-efficient-post-quantum-finance-part-1-digital-signatures/)
+ For more information about signature aggregation (`bklm_one_time_agg_sigs.py`) see this writeup: [https://www.theqrl.org/blog/techniques-for-efficient-post-quantum-finance-part-2-signature-aggregation/](https://www.theqrl.org/blog/techniques-for-efficient-post-quantum-finance-part-2-signature-aggregation/)
+ For more information about the `lattice-algebra` library underlying the code in this repositor, see our introduction here: https://www.theqrl.org/blog/lattice-algebra-library/

## Contributors

Brandon Goodell (lead author), Mitchell "Isthmus" Krawiec-Thayer, Rob Cannon.

Built by [Geometry Labs](https://www.geometrylabs.io) in partnership with [The QRL Foundation](https://qrl.foundation/).

## Running Tests

Run `pip install -r requirements-dev.txt` then see files in `tests` folder

## License

This library is released as free and open-source software under the MIT License, see LICENSE file for details.

## Contact

[info@geometrylabs.io](mailto:info@geometrylabs.io)