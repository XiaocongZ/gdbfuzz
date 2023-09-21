# This class manages the input generation.
# Copyright (c) 2022 Robert Bosch GmbH
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
from __future__ import annotations
from dataclasses import dataclass

import logging as log
import math
import os
import random

import _pylibfuzzer

@dataclass
class CorpusEntry:
    content: bytes
    fname: str
    origin: int
    depth: int
    num_fuzzed: int = 0
    num_childs: int = 0
    weight: float = 1
    burn_in: int = 5

    def compute_weight(self, total_corpus_entries: int):
        self.weight = 1.0

        # Adapted from AFL
        #if self.num_fuzzed:
        #    self.weight *= math.log10(self.num_fuzzed) + 1

        # More childs indicate a good seed
        #if self.num_childs:
        #    self.weight *= self.num_childs / float(total_corpus_entries) + 1

        # The deeper, the better
        #if self.depth:
        #    self.weight *= math.log(self.depth) + 1

        if self.burn_in:
            self.weight *= self.burn_in


    def __str__(self) -> str:
        return f'{self.fname}, depth={self.depth}, num_fuzzed={self.num_fuzzed}, childs={self.num_childs}, weight={self.weight}, burn_in={self.burn_in}'

class InputGeneration:



    def __init__(
            self,
            output_directory: str,
            seeds_directory: str | None = None,
            max_input_length: int = 1024,
            libfuzzer_so_path: str | None = None
    ):
        if libfuzzer_so_path is None:
            libfuzzer_so_path = os.path.join(
                os.path.dirname(__file__),
                '../../../dependencies/libFuzzerSrc/libfuzzer-mutator.so'
            )
            # _pylibfuzzer reads this env var to know where
            # libfuzzer-mutate.so is located.
            os.environ['libfuzzer_mutator_so_path'] = libfuzzer_so_path

        # maximum length of generated inputs in bytes.
        self.max_input_length = max_input_length

        # Corpus entries are stored on disk in this directory.
        self.corpus_directory = os.path.join(output_directory, 'corpus')
        os.mkdir(self.corpus_directory)

        if not os.path.exists(libfuzzer_so_path):
            raise Exception(f'{libfuzzer_so_path=} does not exist.')

        if seeds_directory is not None:
            if not os.path.exists(seeds_directory):
                raise Exception(f'{seeds_directory=} does not exist.')

        # set is for fast contains checks, list is for fast 'random.choice',
        # i.e. selecting random element.
        self.corpus: list[CorpusEntry] = []

        # For the initialization phase, we keep these values to -1
        # The currently selected base input
        self.current_base_input_index: int = -1

        # Index of corpus entry we need to retry (because we target new addresses)
        self.retry_corpus_input_index: int = -1


        if seeds_directory:
            self.add_seeds(seeds_directory)

        if len(self.corpus) == 0:
            # No seeds were specified or all seeds in seeds_directory are too
            # large
            self.add_corpus_entry(b"hi", 0) # Default from fuzzbench :)

        # Setup stared libfuzzer object.
        _pylibfuzzer.initialize(max_input_length)

        self.current_input = None
        self.choose_new_baseline_input()

    def add_seeds(self, seeds_directory: str) -> None:
        """Add each seed in seeds_directory to the corpus.

        Inputs larger than self.max_input_length are not added.
        """
        for filename in sorted(os.listdir(seeds_directory)):
            filepath = os.path.join(seeds_directory, filename)
            if not os.path.isfile(os.path.join(filepath)):
                continue
            with open(filepath, 'rb') as f:
                seed = f.read()
                if len(seed) > self.max_input_length:
                    log.warning(
                        f'Seed {filepath=} was not added to the corpus '
                        f'because the seed length ({len(seed)}) was too large'
                        f' {self.max_input_length=}.'
                    )
                    continue
                log.debug(f'Seed {filepath=} added.')
                if seed not in self.corpus:
                    self.add_corpus_entry(seed, 0)

    def add_corpus_entry(self, input: bytes, timestamp:int) -> CorpusEntry:


        filepath = os.path.join(
            self.corpus_directory,
            f'id:{str(len(self.corpus))},orig:{self.current_base_input_index},time:{timestamp}'
        )
        with open(filepath, 'wb') as f:
            f.write(input)


        depth = 0
        if self.current_base_input_index >= 0:
            depth = self.corpus[self.current_base_input_index].depth + 1
            self.corpus[self.current_base_input_index].num_childs +=1

        entry = CorpusEntry(input, filepath, self.current_base_input_index, depth)
        self.corpus.append(entry)

        return entry

    def choose_new_baseline_input(self):
        self.inputs_to_switch_baseline = 50
        energy_sum = 0
        cum_energy = []
        for i in self.corpus:
            i.compute_weight(len(self.corpus))
            energy_sum += i.weight
            cum_energy.append(energy_sum)

        # Draw new corpus entry according to energy
        self.current_base_input_index =  random.choices(range(len(cum_energy)), cum_weights=cum_energy).pop()

        chosen_entry = self.corpus[self.current_base_input_index]
        chosen_entry.num_fuzzed += 1
        if chosen_entry.burn_in:
            chosen_entry.burn_in -= 1

    def get_baseline_input(self) -> bytes:
        return self.corpus[self.current_base_input_index].content

    def get_current_input(self) -> bytes:
        return self.current_input

    def generate_input(self) -> bytes:
        #for now, switch baseline after 50 inputs
        self.inputs_to_switch_baseline -= 1
        if self.inputs_to_switch_baseline == 0:
            log.info('choose_new_baseline_input')
            self.choose_new_baseline_input()

        generated_inp = _pylibfuzzer.mutate(self.corpus[self.current_base_input_index].content)
        self.current_input = generated_inp
        return generated_inp
