// This example program reads data from serial and parses it as json.
// Copyright (c) 2022 Robert Bosch GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "Arduino.h"
#include <signal.h>

#ifndef LED_BUILTIN
#define LED_BUILTIN 13
#endif


char *buf = 0;
char buf_same_prefix[10];
size_t input_len = 0;
int led_state = 0;
uint count = 0;

#define FUZZ_INPUT_SIZE 2048

void setup() {
    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, HIGH);
    Serial.begin(38400);

    buf = (char*)calloc(1, FUZZ_INPUT_SIZE);
    if(!buf) {
        digitalWrite(LED_BUILTIN, LOW);
        delay(1000000);
        return;
    }
}

void serial_read_bytes(char *buf, size_t length) {
    size_t bytes_read = 0;

    while (bytes_read < length) {
        if (!Serial.available()) continue;
        char byte = Serial.read();
        buf[bytes_read] = byte;
        bytes_read += 1;
    }
}

void process_data(char* buffer, unsigned int length) {
	char stack_array[20];
    char match_string[] = "bug!1234";
    bool match = true;
    for (int i = 0; i < 8; i++){
        if (match == true && length > i && buffer[i] == match_string[i]){
            buf_same_prefix[i] = buffer[i];
        }
        else{
            match = false;
            buf_same_prefix[i] = 0;
        }
    }
    /*
	if( length > 0 && buffer[0] == 'b')
		if( length > 1 && buffer[1] == 'u')
			if( length > 2 && buffer[2] == 'g')
				if( length > 3 && buffer[3] == '!')
                    if( length > 4 && buffer[4] == '1')
                        if( length > 5 && buffer[5] == '2')
                            if( length > 6 && buffer[6] == '3')
                                if( length > 7 && buffer[7] == '4'){
                					memcpy(stack_array, buffer, length);
                                    Serial.write(stack_array[3]);
                				}
    */
}

void loop() {
    count++;
    if (led_state == 0) {
        digitalWrite(LED_BUILTIN, HIGH);
        led_state = 1;
    } else {
        digitalWrite(LED_BUILTIN, LOW);
        led_state = 0;
    }

    // Notify that we request a new input
    Serial.write('A');

    uint32_t response_length = 0;
    serial_read_bytes((char*)&response_length, 4);

    if (response_length > FUZZ_INPUT_SIZE)
    {
        Serial.println("ERROR: Received input with length > 2048");
        while(1){ delay(100); }
    }
    //socket_read_bytes(connection_fd, (void *)buf, response_length);
    serial_read_bytes(buf, (size_t) response_length);

    process_data(buf, response_length);
}
