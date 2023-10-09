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

#define FUZZ_INPUT_SIZE 2048
#define FUZZ_PREFIX_SIZE 64

char *buf = 0;
char buf_same_prefix[FUZZ_PREFIX_SIZE];
size_t input_len = 0;
int led_state = 0;
uint count = 0;



void toggle_led() {
    if (led_state == 0) {
        digitalWrite(LED_BUILTIN, HIGH);
        led_state = 1;
    } else {
        digitalWrite(LED_BUILTIN, LOW);
        led_state = 0;
    }
}

void setup() {
    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, LOW);
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
	char stack_array[FUZZ_PREFIX_SIZE];
    char match_string[] = "bug!bufferoverflowIn programming and software development, fuzzing or fuzz testing is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program.";
    for (int i = 0; i < FUZZ_PREFIX_SIZE; i++){
        if (length > i && buffer[i] == match_string[i]){
            buf_same_prefix[i] = buffer[i];
        }
        else{
            break;
        }
    }

    if( length > 0 && buffer[0] == 'b')
    	if( length > 1 && buffer[1] == 'u')
    		if( length > 2 && buffer[2] == 'g')
    			if( length > 3 && buffer[3] == '!')
    				if( length > 4 && buffer[4] == 'b')
    					if( length > 5 && buffer[5] == 'u')
    						if( length > 6 && buffer[6] == 'f')
    							if( length > 7 && buffer[7] == 'f')
    								if( length > 8 && buffer[8] == 'e')
    									if( length > 9 && buffer[9] == 'r')
    										if( length > 10 && buffer[10] == 'o')
    											if( length > 11 && buffer[11] == 'v')
    												if( length > 12 && buffer[12] == 'e')
    													if( length > 13 && buffer[13] == 'r')
    														if( length > 14 && buffer[14] == 'f')
    															if( length > 15 && buffer[15] == 'l')
    																if( length > 16 && buffer[16] == 'o')
    																	if( length > 17 && buffer[17] == 'w')
    																		if( length > 18 && buffer[18] == 'I')
    																			if( length > 19 && buffer[19] == 'n')
    																				if( length > 20 && buffer[20] == ' ')
    																					if( length > 21 && buffer[21] == 'p')
    																						if( length > 22 && buffer[22] == 'r')
    																							if( length > 23 && buffer[23] == 'o')
    																								if( length > 24 && buffer[24] == 'g')
    																									if( length > 25 && buffer[25] == 'r')
    																										if( length > 26 && buffer[26] == 'a')
    																											if( length > 27 && buffer[27] == 'm')
    																												if( length > 28 && buffer[28] == 'm')
    																													if( length > 29 && buffer[29] == 'i')
    																														if( length > 30 && buffer[30] == 'n')
    																															if( length > 31 && buffer[31] == 'g')
    																																if( length > 32 && buffer[32] == ' ')
    																																	if( length > 33 && buffer[33] == 'a')
    																																		if( length > 34 && buffer[34] == 'n')
    																																			if( length > 35 && buffer[35] == 'd')
    																																				if( length > 36 && buffer[36] == ' ')
    																																					if( length > 37 && buffer[37] == 's')
    																																						if( length > 38 && buffer[38] == 'o')
    																																							if( length > 39 && buffer[39] == 'f')
    																																								if( length > 40 && buffer[40] == 't')
    																																									if( length > 41 && buffer[41] == 'w')
    																																										if( length > 42 && buffer[42] == 'a')
    																																											if( length > 43 && buffer[43] == 'r')
    																																												if( length > 44 && buffer[44] == 'e')
    																																													if( length > 45 && buffer[45] == ' ')
    																																														if( length > 46 && buffer[46] == 'd')
    																																															if( length > 47 && buffer[47] == 'e')
    																																																if( length > 48 && buffer[48] == 'v')
    																																																	if( length > 49 && buffer[49] == 'e')
    																																																		if( length > 50 && buffer[50] == 'l')
    																																																			if( length > 51 && buffer[51] == 'o')
    																																																				if( length > 52 && buffer[52] == 'p')
    																																																					if( length > 53 && buffer[53] == 'm')
    																																																						if( length > 54 && buffer[54] == 'e')
    																																																							if( length > 55 && buffer[55] == 'n')
    																																																								if( length > 56 && buffer[56] == 't')
    																																																									if( length > 57 && buffer[57] == ',')
    																																																										if( length > 58 && buffer[58] == ' ')
    																																																											if( length > 59 && buffer[59] == 'f')
    																																																												if( length > 60 && buffer[60] == 'u')
    																																																													if( length > 61 && buffer[61] == 'z')
    																																																														if( length > 62 && buffer[62] == 'z')
    																																																															if( length > 63 && buffer[63] == 'i')

                                                                                                                                                                                                                                                                    {
                                                                                                                                                                                                                                                    					memcpy(stack_array, buffer, length);
                                                                                                                                                                                                                                                                        Serial.write(stack_array[FUZZ_PREFIX_SIZE]);
                                                                                                                                                                                                                                                    				}

}

void loop() {
    count++;
    toggle_led();

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
