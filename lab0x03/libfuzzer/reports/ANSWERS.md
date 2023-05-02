# Answers

This document contains the answers for the AFL++ part of the lab

## You did not change `is_png_chunk_valid` in this lab, does it affect the performance of libFuzzer's default mutator? What about the example PNG mutator and your custom YOLO PNG mutator?

We expect that this **affects the performance of the default mutator**. Indeed, this one is totally **unaware of the YOLO PNG format structure and grammar** and will not mutate accordingly. The CRC being a specific value for the chunk, we expect that random mutations will prevent this check from passing on most mutations, **preventing discovering of new paths**.

However, for both the PNG mutator and YOLO PNG mutator, we took care of, **during serialization, computing the correct CRC checksum** to make sure we don't have rogue chunks with an invalid CRC checksum.

## How many PCs are covered within `100000 fuzzing runs` with your `fuzzer_store_png_rgba`, equipped with libFuzzer's default mutator, the example PNG mutator, and your custom YOLO PNG mutator separately? Do these numbers reflect the extent to which `store_png` has been tested?

* Default mutator: 100
* Example PNG mutator: 106
* Custom YOLO PNG mutator: 95

The reported PCs show the total number of code blocks or edges covered by executing the current corpus. These numbers can be seen as reflecting or not the extent to which `store_png` is tested:

* It kind of reports the extend to which this function has been tested because it shows the reached coverage. Therefore, a mutator which would yield tremendously higher coverage would let us suppose that the desired function has been more explored (assuming all functions would evenly be explored during fuzzing). **HOWEVER** in our context:
* These numbers do not accurately reflect the exploration of this function because we see **very little difference between these**. We even see that **our custom mutator explored less** : we suppose that this is because **our mutator not going to error edges of the PNG *parsing***, it covers less that the others **but in the PNG parsing phase**. This is expected. Therefore, this metric does not seem to lead us to accurate conclusions about the exploration of the store_png function.

## Do you think the mutator you customized (that aims at only generating well-formatted YOLO PNG inputs) helpful for finding bugs in `load_png`? Why?

This mutator can still reveal useful. Indeed, load_png has **other tests that may not be covered** by our well formed input, notably during the **decompression phase**.

However, we must recognize that **less functions edges will be explored** in the PNG parsing phase (as the trickier edges should not be explored). We therefore should also **keep other mutators to try being complete** in our exploration of the load_png function.
