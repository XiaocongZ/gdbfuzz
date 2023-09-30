# This is the abstract base connection class
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
import multiprocessing as mp
import queue
import signal
import logging as log
import time
from abc import abstractmethod
from typing import Any
import asyncio


class ConnectionBaseClass(mp.Process):
    def __init__(
            self,
            stop_responses: mp.Queue[tuple[str, Any]],
            SUTConnection_config: configparser.SectionProxy,
            inputs: mp.Queue[bytes],
            reset_sut
    ):
        super().__init__()
        self.stop_responses = stop_responses
        self.SUTConnection_config = SUTConnection_config
        self.inputs = inputs
        self.reset_sut_function = reset_sut


    def start(self):
        try:
            self.connect(self.SUTConnection_config)
        except Exception as e:
            log.warning(e)

        super().start()
        # Give connection some time to start
        time.sleep(1)

    async def task_recv(self) -> None:
        while True:
            await asyncio.sleep(0.01)
            if self.wait_for_input_request(False):
                log.debug("serial input acquired")
                self.stop_responses.put(('input request', ''))

    async def task_send(self) -> None:
        while True:
            await asyncio.sleep(0.01)
            try:
                fuzz_input = self.inputs.get(block=False)
                self.send_input(fuzz_input)
            #todo which Exception
            except queue.Empty as e:
                pass


    async def recv_send(self) -> None:
        task1 = asyncio.create_task(self.task_recv())
        task2 = asyncio.create_task(self.task_send())
        await asyncio.gather(task1, task2)

    def run(self) -> None:
        signal.signal(signal.SIGUSR1, self.on_exit)
        signal.signal(signal.SIGUSR2, self.on_reset)
        # Parts of the connect process might need to be done within the subprocess,
        # because the connection requires the target to run.
        # This is done to handle connection issues easier,
        # Since only a new connection process needs to be started therefore
        self.connect_async()
        asyncio.run(self.recv_send())


    def reset_sut(self):
        self.reset_sut_function()

    def on_reset(self, signum: Any, frame: Any) -> None:
        log.info("signal reset")
        self.disconnect()
        self.connect(self.SUTConnection_config)
        log.info("signal reset end")

    def on_exit(self, signum: Any, frame: Any) -> None:
        self.disconnect()
        exit(0)

    def connect(self, SUTConnection_config: configparser.SectionProxy) -> None:
        """[Optional] Establish connection to SUT while it is halted"""
        ...

    def connect_async(self) -> None:
        """[Optional] Establish connection to SUT asynchronously, while it is executed further"""
        ...

    @abstractmethod
    def send_input(self, fuzz_input: bytes) -> None:
        """Sends 'fuzz_input' to SUT"""
        ...

    @abstractmethod
    def wait_for_input_request(self) -> None:
        """Blocks until SUT can receive input"""
        ...

    def disconnect(self) -> None:
        """[Optional], free connection resources

        Example: Close TCP socket.
        """
        ...
