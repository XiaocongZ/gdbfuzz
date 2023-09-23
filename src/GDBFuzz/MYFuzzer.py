# This is the main controller class for GDBFuzz.
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

import configparser
import hashlib
import json
import logging as log
import os
import re
import time
import uuid
from configparser import ConfigParser
from typing import Any

import attr
import ast
import hashlib

from GDBFuzz import graph
from GDBFuzz import util

from GDBFuzz.fuzz_wrappers.InputGeneration import CorpusEntry, InputGeneration
###
from GDBFuzz.MYFuzzerStats import FuzzerStats
from GDBFuzz.gdb.GDB import GDB
from GDBFuzz.modes.QEMUInstance import QEMUInstance
from GDBFuzz.modes.SUTInstance import SUTInstance
from GDBFuzz.modes.SUTRunsOnHostInstance import SUTRunsOnHostInstance
from GDBFuzz.SUTException import SUTException
from GDBFuzz.visualization.Visualizations import Visualizations


class GDBFuzzer:

    def __init__(self, config: ConfigParser, config_file_path: str) -> None:

        self.before_fuzzing(config, config_file_path)

        self.run(config)

        self.after_fuzzing()
        raise SystemExit(0)

    def before_fuzzing(
            self,
            config: ConfigParser,
            config_file_path: str
    ) -> None:
        self.max_breakpoints = config['SUT'].getint('max_breakpoints')
        self.output_directory = \
            config['LogsAndVisualizations']['output_directory']

        self.init_fuzzer_stats(config_file_path)
        self.init_components(config)
        self.init_memory_regions(config)

        self.hash_record = dict()

        self.crashes_directory = os.path.join(
            self.output_directory,
            'crashes'
        )
        os.mkdir(self.crashes_directory)

    def init_memory_regions(self, config: ConfigParser) -> None:
        self.memory_regions = ast.literal_eval(config['SUTMem']['memory_regions'])
        self.stack_base_addr = int(config['SUTMem']['stack_base_addr'], 16)

    def init_fuzzer_stats(self, config_file_path: str) -> None:
        self.fuzzer_stats = FuzzerStats()
        self.fuzzer_stats.start_time_epoch = int(time.time())
        self.fuzzer_stats.start_time = \
            time.strftime('%d_%b_%Y_%H:%M:%S_%Z', time.localtime())
        self.fuzzer_stats.config_file_path = config_file_path
        self.write_fuzzer_stats()

    def init_components(self, config: ConfigParser) -> None:
        #TODO visualization
        self.visualizations: Visualizations | None = None
        if config['LogsAndVisualizations'].getboolean('enable_UI'):
            self.visualizations = Visualizations(
                self.fuzzer_stats,
                self.output_directory,
                self.ghidra.CFG()
            )
            self.visualizations.daemon = True
            self.visualizations.start()

        seeds_directory: str | None = config['Fuzzer']['seeds_directory']
        if seeds_directory == '':
            seeds_directory = None
        self.input_gen = InputGeneration(
            self.output_directory,
            seeds_directory,
            config['Fuzzer'].getint('maximum_input_length')
        )

    #TODO
    def init_SUT(self, config: ConfigParser) -> SUTInstance:
        if config['SUT']['target_mode'] == 'Hardware':
            return SUTInstance(config)
        if config['SUT']['target_mode'] == 'QEMU':
            return QEMUInstance(config)
        if config['SUT']['target_mode'] == 'SUTRunsOnHost':
            return SUTRunsOnHostInstance(config)

        raise Exception(
            'Unknown config target_mode', config['SUT']['target_mode']
        )

    def run(self, config: ConfigParser) -> None:
        single_run_timeout = config['Fuzzer'].getint('single_run_timeout')
        stop_time = config['Fuzzer'].getint('total_runtime') + int(time.time())

        while stop_time >= int(time.time()):
            with self.init_SUT(config) as sut:
                self.start_fuzzing(
                    sut,
                    single_run_timeout,
                    stop_time
                )

    def after_fuzzing(self) -> None:
        self.fuzzer_stats.end_time_epoch = int(time.time())

        self.write_fuzzer_stats()

        log.info('Fuzzing finished. Exiting.')

    def start_fuzzing(
            self,
            sut: SUTInstance,
            single_run_timeout: int,
            stop_time: int
    ):
        self.input_gen.choose_new_mutated_input()
        self.fuzzer_stats.runs += 1

        stop_reason, stop_info = None, None
        while stop_time >= int(time.time()):

            # Update fuzzer stats every minute
            if int(time.time()) > (self.last_stat_update + 60):
                self.write_fuzzer_stats()

            if stop_reason != 'input request':
                sut.gdb.continue_execution()

            stop_reason, stop_info = sut.gdb.wait_for_stop(
                timeout=single_run_timeout
            )

            log.info(f"stop reason: {stop_reason}")

            if stop_reason == 'input request':
                probed = self.on_input_request(sut)
                if probed:
                    return []

            elif stop_reason == 'breakpoint hit':
                log.error("unimplemented")
                raise SystemExit(1)

            elif stop_reason == 'interrupt':
                # In this case, this is a sw breakpoint hit.
                log.error("unimplemented")
                raise SystemExit(1)

            elif stop_reason == 'timed out':
                self.on_timeout(current_input, sut.gdb)
                return []
            elif stop_reason == 'crashed' or stop_reason == 'exited':
                self.on_crash(current_input, sut.gdb)
                return []
            elif stop_reason == 'notify_running':
                log.info('notify_running')
            else:
                log.error(f'Unexpected {stop_reason=} {stop_info=}')
                self.on_crash(current_input, sut.gdb)
                return []

        return []

    def on_crash(
            self,
            current_input: bytes,
            gdb: GDB
    ) -> None:
        log.warn('SUT crash detected')
        self.fuzzer_stats.crashes += 1
        # Get address where crash occured
        try:
            response = gdb.send('-stack-list-frames')
        except TimeoutError:
            # The SUT just crashed, we might not be connected anymore.
            log.warn(
                'Timed out waiting for crashing input stacktrace '
                f'{current_input=}'
            )
            self.write_crashing_input(current_input, str(uuid.uuid4()))
            return
        if 'payload' not in response or 'stack' not in response['payload']:
            log.warn(
                'Invalid payload for crashing input stacktrace '
                f'{current_input=}'
            )
            self.write_crashing_input(current_input, str(uuid.uuid4()))
            return
        stacktrace = ''
        for frame in response['payload']['stack']:
            stacktrace += ' ' + frame['addr']

        # Limit to 100
        if len(stacktrace) > 100:
            stacktrace = stacktrace[0:100]

        # Make string os file name friendly
        stacktrace = "".join([c for c in stacktrace if re.match(r'\w', c)])
        #hashed_stacktrace = hashlib.sha1()
        #hashed_stacktrace.update(stacktrace)
        #stacktrace_digest = hashed_stacktrace.hexdigest()

        self.write_crashing_input(current_input, stacktrace)

    def write_crashing_input(
            self,
            current_input: bytes,
            filename: str
    ) -> None:
        filepath = os.path.join(self.crashes_directory, filename)
        if os.path.isfile(filepath):
            log.info(f'Found duplicate crash with {current_input=}')
            return

        with open(filepath, 'wb') as f:
            log.info(f'New crash with {current_input=}')
            f.write(current_input)

    def on_timeout(
            self,
            current_input: bytes,
            gdb: GDB
    ) -> None:
        try:
            self.fuzzer_stats.timeouts += 1
            stacktrace = ''
            gdb.interrupt()
            # We dont get acknowledge when target system is stopped, so
            # wait for 1 second for target system to stop.
            #time.sleep(1)

            response = gdb.send('-stack-list-frames')
            for frame in response['payload']['stack']:
                stacktrace += str(frame['addr']) + ' '
            log.info(f'Timeout input {stacktrace=}')
        except Exception as e:
            log.info(f'Failed to get stacktrace for timeout {e=}')
        if stacktrace is None:
            # use input for deduplication
            stacktrace = current_input
        # Limit to 100
        if len(stacktrace) > 100:
            stacktrace = stacktrace[0:100]

        # Make string os file name friendly
        stacktrace = "".join([c for c in stacktrace if re.match(r'\w', c)])

        filepath = os.path.join(
            self.crashes_directory,
            'timeout_' + stacktrace
        )
        if os.path.isfile(filepath):
            log.info(f'Found duplicate timout input {current_input=}')
            return
        with open(filepath, 'wb') as f:
            log.info(f'Found new timeout {current_input=}')
            f.write(current_input)

    def on_input_request(
            self,
            sut: SUTInstance
    ) -> bool:

        SUT_input, is_depleted = self.input_gen.get_next_input()
        log.info(SUT_input)
        if is_depleted:
            log.info('probe')
            #probing memory regions
            sut.gdb.interrupt()
            self.probe(sut.gdb)
            sut.gdb.continue_execution()
            return True
        else:
            sut.SUT_connection.send_input(SUT_input)
            return False

    def write_fuzzer_stats(self) -> None:
        self.last_stat_update = int(
            time.time())

        self.fuzzer_stats.runtime = int(
            time.time()) - self.fuzzer_stats.start_time_epoch
        if self.fuzzer_stats.runtime > 1:
            self.fuzzer_stats.runs_per_sec = self.fuzzer_stats.runs / \
                self.fuzzer_stats.runtime

        stats_file_path = os.path.join(
            self.output_directory,
            'fuzzer_stats'
        )
        # Print corpus statistics
        if hasattr(self, 'input_gen'):
            self.fuzzer_stats.corpus_state = list(map(CorpusEntry.__str__, self.input_gen.corpus))

        with open(stats_file_path, 'w') as f:
            f.write(json.dumps(
                attr.asdict(self.fuzzer_stats),
                indent=4
            ))

    def write_coverage_data(self, address: int) -> None:
        runtime = int(time.time()) - self.fuzzer_stats.start_time_epoch

        stats_file_path = os.path.join(
            self.output_directory,
            'plot_data'
        )
        with open(stats_file_path, 'a') as f:
            f.write(f'{runtime} {hex(address)}\n')

    def probe(self, gdb: GDB) -> str:
        #msp_num = gdb.register_name_to_number("$msp")
        #print("msp_num", msp_num)

        #sp = gdb.read_register(13)
        #stack_mem = gdb.read_memory(sp, self.stack_base_addr - sp)

        regions_to_probe = ['buf_same_prefix']
        mem = ''
        for region in self.memory_regions:
            if region[0] in regions_to_probe:
                region_mem = gdb.read_memory(region[1], region[2])
                mem += region_mem
                #time.sleep(0.2)

        #mem = mem + stack_mem
        log.info(mem)
        hash = self.compute_hash(bytes.fromhex(mem))
        log.info(hash)
        #hashing and recording
        current_input = self.input_gen.get_current_input()
        log.info(current_input)
        if not hash in self.hash_record:
            self.hash_record[hash] = None
            #todo modify
            packed_content = CorpusEntry.static_pack_contents(current_input)
            self.input_gen.add_corpus_entry(packed_content, int(time.time()) - self.fuzzer_stats.start_time_epoch)
            log.info("new hash")
        else:
            log.info("repeated hash")
        return hash

    def compute_hash(self, data: bytes) -> str:
        h = hashlib.md5()
        h.update(data)
        return h.hexdigest()
