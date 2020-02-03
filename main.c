/* avrng - AVR-based Videocrypt card firmware for hacktv                 */
/*=======================================================================*/
/* Copyright 2019 Marco Wabbel <marco@familie-wabbel.de>                 */
/*                                                                       */
/* This program is free software: you can redistribute it and/or modify  */
/* it under the terms of the GNU General Public License as published by  */
/* the Free Software Foundation, either version 3 of the License, or     */
/* (at your option) any later version.                                   */
/*                                                                       */
/* This program is distributed in the hope that it will be useful,       */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/* GNU General Public License for more details.                          */
/*                                                                       */
/* You should have received a copy of the GNU General Public License     */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>. */
/*                                                                       */
/* Original Copyright for the base of this Firmware goes to:             */
/*              Philip Heron <phil@sanslogic.co.uk>                      */
/*                                                                       */
/* Copyright for VC Issue 07 / 09 hash-algo code goes to:                */
/*             Alex James <alexanderjames1981@gmail.com> and/or          */
/*              Philip Heron <phil@sanslogic.co.uk>                      */

/* Hardware setup:
 *
 * F_CPU is 3.57 MHz.
 * PB6 is I/O, 9-bit software serial.
 * Timer1 is used to drive I/O on PB6 at x3 actual rate.
 * Interrupt Timing = F_CPU / (BAUDRATE * 3)
 * Communication is 8-ODD-1 so 9 Bit UART is needed
*/

#include "config.h"
#include <avr/io.h>
#include <avr/pgmspace.h>
#include <avr/interrupt.h>
#include <util/delay.h>
#include "uart.h"
#include <string.h>
#include <avr/eeprom.h>

#define VC_TAC 0
#define VC_SKY 1
#define cdelay 40

/* Standard responses */
const uint8_t _atr[] PROGMEM = { 0x3f , 0xfa , 0x11 , 0x25 , 0x05 , 0x00 , 0x01 , 0xb0 , 0x02 , 0x3b , 0x36 , 0x4d , 0x59 , 0x02 , 0x80 , 0x81
};
const uint8_t _ans_7c[] PROGMEM ={ 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
const uint8_t _mtv1[] PROGMEM = { 0x78, 0x8e, 0x17, 0xce, 0x7b, 0x5a, 0xd5, 0x2d, 0x9b
};
const uint8_t _mtv2[] PROGMEM = { 0x78, 0x80, 0x0b, 0x77, 0x50, 0xda, 0x85, 0x98, 0xdf
};
const uint8_t _mtv3[] PROGMEM = { 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
const uint8_t _ans_tac[] PROGMEM = { 0x7a, 0xd8, 0x20, 0x20, 0x54, 0x41, 0x43, 0x2D, 0x4D, 0x4F, 0x44, 0x45, 0x20, 0x20, 0x20, 0x48, 0x41, 0x56, 0x45, 0x20, 0x46, 0x55, 0x4E, 0x20, 0x3A, 0x29
};
const uint8_t _ans_sky[] PROGMEM = { 0x7a, 0xd8, 0x20, 0x53, 0x4B, 0x59, 0x37, 0x2D, 0x4D, 0x4F, 0x44, 0x45, 0x20, 0x20, 0x20, 0x48, 0x41, 0x56, 0x45, 0x20, 0x46, 0x55, 0x4E, 0x20, 0x3A, 0x29
};
const uint8_t _ans_xtea[] PROGMEM = { 0x7a, 0xd8, 0x20, 0x58, 0x54, 0x45, 0x41, 0x2D, 0x4D, 0x4F, 0x44, 0x45, 0x20, 0x20, 0x20, 0x48, 0x41, 0x56, 0x45, 0x20, 0x46, 0x55, 0x4E, 0x20, 0x3A, 0x29
};
const uint8_t _ans_iss09[] PROGMEM = { 0x7a, 0xd8, 0x20, 0x53, 0x4b, 0x59, 0x39, 0x2D, 0x4D, 0x4F, 0x44, 0x45, 0x20, 0x20, 0x20, 0x48, 0x41, 0x56, 0x45, 0x20, 0x46, 0x55, 0x4E, 0x20, 0x3A, 0x29
};
const uint8_t _ans_keyup[] PROGMEM = { 0x7a, 0xd8, 0x21, 0x4B, 0x45, 0x59, 0x55, 0x50, 0x44, 0x41, 0x54, 0x45, 0x21, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20
};
const uint8_t _ans_7a[] PROGMEM = { 0x7a, 0x80, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20
};
const uint8_t _ans_block[] PROGMEM = { 0x7a, 0xd8, 0x54, 0x48, 0x49, 0x53, 0x20, 0x43, 0x48, 0x41, 0x4e, 0x4e, 0x45, 0x4c, 0x20, 0x49, 0x53, 0x20, 0x42, 0x4c, 0x4f, 0x43, 0x4b, 0x45, 0x44, 0x20
};
const uint8_t _ack[] PROGMEM = { 0x90, 0x00
};

/* EEPROM VALUES */
const uint32_t _xtea_key[4] EEMEM = {
    0x00112233,0x44556677,0x8899AABB,0xCCDDEEFF
};

/* Videocrypt key used for Sky 09 series cards */

const uint8_t sky09_key[216] EEMEM = {
    0x91, 0x61, 0x9d, 0x53, 0xb3, 0x27, 0xd5, 0xd9,
	0x0F, 0x59, 0xa6, 0x6f, 0x73, 0xfb, 0x99, 0x4c,
	0xfb, 0x45, 0x54, 0x8e, 0x20, 0x5f, 0xb3, 0xb1,
	0x38, 0xd0, 0x6b, 0xa7, 0x40, 0x39, 0xed, 0x2a,
	0xda, 0x43, 0x8d, 0x51, 0x92, 0xd6, 0xe3, 0x61,
	0x65, 0x8c, 0x71, 0xe6, 0x84, 0x65, 0x87, 0x03,
	0x55, 0xbc, 0x64, 0x07, 0xbb, 0x79, 0x9e, 0x40,
	0x97, 0x89, 0xc4, 0x14, 0x8f, 0x8b, 0x41, 0x4d,
	0x2a, 0xaa, 0xe8, 0xe1, 0x08, 0xcd, 0x82, 0x43,
	0x8f, 0x6f, 0x36, 0x9b, 0x72, 0x47, 0xf2, 0xa4,
	0x49, 0xdd, 0x8b, 0x6e, 0x26, 0xc6, 0xbf, 0xb7,
	0xd8, 0x44, 0xc3, 0x70, 0xa3, 0x4c, 0xb6, 0xb2,
	0x37, 0x9b, 0x09, 0xdf, 0x32, 0x28, 0x24, 0x86,
	0x8d, 0x5f, 0xe6, 0x4b, 0x5d, 0xd0, 0x2f, 0xdb,
	0xac, 0x2e, 0x78, 0x1e, 0xcc, 0x52, 0xc1, 0x61,
	0xea, 0x82, 0xca, 0xb3, 0xf4, 0x8f, 0x63, 0x8e,
	0x6c, 0xbc, 0xaf, 0xc3, 0x2b, 0xb5, 0xdc, 0x90,
	0xf9, 0x05, 0xea, 0x51, 0x46, 0x9d, 0xe2, 0x60,
	0x01, 0x35, 0x59, 0x79, 0x00, 0x00, 0x55, 0x0F,
	0x00, 0x00, 0x00, 0x00, 0x10, 0x6e, 0x1c, 0xbd,
	0xfe, 0x44, 0xeb, 0x79, 0xf3, 0xab, 0x5d, 0x23,
	0xb3, 0x20, 0xd2, 0xe7, 0xfc, 0x00, 0x03, 0x6f,
	0xd8, 0xb7, 0xf7, 0xf3, 0x55, 0x72, 0x47, 0x13,
	0x7b, 0x0c, 0x08, 0x01, 0x8a, 0x2c, 0x70, 0x56,
	0x0a, 0x85, 0x18, 0x14, 0x43, 0xc9, 0x46, 0x64,
	0x6c, 0x9a, 0x99, 0x59, 0x0a, 0x6c, 0x40, 0xd5,
	0x17, 0xb3, 0x2c, 0x69, 0x41, 0xe8, 0xe7, 0x0e //26
};


/* Videocrypt key used for "The Adult Channel" cards */

const uint8_t tac_key[96] EEMEM = {
    0xd9, 0x45, 0x08, 0xdb, 0x7c, 0xf9, 0x56, 0xf7,
    0x58, 0x18, 0x22, 0x54, 0x38, 0xcd, 0x3d, 0x94,
    0x09, 0xe6, 0x8e, 0x0d, 0x9a, 0x86, 0xfc, 0x1c,
	0xa0, 0x19, 0x8f, 0xbc, 0xfd, 0x8d, 0xd1, 0x57,
	0x56, 0xf2, 0xb6, 0x4f, 0xc9, 0xbd, 0x2a, 0xb3,
	0x9d, 0x81, 0x5d, 0xe0, 0x05, 0xb5, 0xb9, 0x26,
	0x67, 0x3c, 0x65, 0xa0, 0xba, 0x39, 0xc7, 0xaf,
	0x33, 0x24, 0x47, 0xa6, 0x20, 0x1e, 0x14, 0x6f,
	0x48, 0x9b, 0x4d, 0xa6, 0xf9, 0xd9, 0xdf, 0x6e,
	0xac, 0x84, 0xfa, 0x8b, 0x2e, 0xb6, 0x76, 0x19,
	0xc1, 0xb0, 0xa3, 0xbb, 0x0c, 0xfd, 0x70, 0x72,
	0xca, 0x55, 0xef, 0xa0, 0x7f, 0xbf, 0x59, 0xad //11
};

/* Videocrypt key used for Sky 07 series cards */

const uint8_t sky07_key[56] EEMEM = {
    0x65, 0xe7, 0x71, 0x1a, 0xb4, 0x88, 0xd7, 0x76,
    0x28, 0xd0, 0x4c, 0x6e, 0x86, 0x8c, 0xc8, 0x43,
    0xa9, 0xec, 0x60, 0x42, 0x05, 0xf2, 0x3d, 0x1c,
    0x6c, 0xbc, 0xaf, 0xc3, 0x2b, 0xb5, 0xdc, 0x90,
    0xf9, 0x05, 0xea, 0x51, 0x46, 0x9d, 0xe2, 0x60,
    0x70, 0x52, 0x67, 0x26, 0x61, 0x49, 0x42, 0x09,
    0x50, 0x99, 0x90, 0xa2, 0x36, 0x0e, 0xfd, 0x39 //6
};

static uint8_t vc_key[216];

uint32_t xtea_key[4];



/* Some helpers */
static uint8_t check = 0;
static uint8_t invert = 1;
uint8_t mode = 9;
uint8_t _mode = 9;
uint8_t osdctr = 0;
int8_t _kupd = -1;


/* I/O buffers */
static uint8_t _ib[32];
static uint8_t _ob[9] = {0x78,0,0,0,0,0,0,0,0};

uint8_t _getParity(uint8_t p)
     {
      p = p ^ (p >> 4 | p << 4);
      p = p ^ (p >> 2);
      p = p ^ (p >> 1);
      return p & 1;
     }

uint8_t _reverse_byte(uint8_t xx){
if(invert){
	xx =((xx & 0xaa) >> 1) | ((xx & 0x55) << 1);
	xx =((xx & 0xcc) >> 2) | ((xx & 0x33) << 2);
	xx =((xx & 0xf0) >> 4) | ((xx & 0x0f) << 4);
	xx ^= 0xFF;
    }
	return xx;
}

void _vc_kernel09(const uint8_t in, uint8_t *answ)
{
	uint8_t a, b, c, d;
  	uint16_t m;
  	uint8_t i;

  	a = in;
  	for (i = 0; i <= 4; i += 2)
  	{
		b = answ[i] & 0x3F;
    	b =  vc_key[b] ^ vc_key[b + 0x98];
    	c = a + b - answ[i+1];
    	d = (answ[i] - answ[i+1]) ^ a;
    	m = d * c;
    	answ[i + 2] ^= (m & 0xFF);
    	answ[i + 3] += m >> 8;
    	a = (a << 1) | (a >> 7);
    	a += 0x49;
  	}

  	m = answ[6] * answ[7];
  	a = (m & 0xFF) + answ[0];
  	if (a < answ[0]) a++;
  	answ[0] = a + 0x39;
  	a = (m >> 8) + answ[1];
  	if (a < answ[1]) a++;
  	answ[1] = a + 0x8F;
}

void _vc_rand_seed_sky09(void)
{
	int i;
	uint8_t b = 0;
	uint8_t answ[8];

	/* Reset answers */
	for (i = 0; i < 8; i++) answ[i] = 0;
	for (i = 0; i < 27; i++) _vc_kernel09(_ib[i],answ);

	/* Calculate signature */
	for (i = 27; i < 31; i++)
	{
		_vc_kernel09(b, answ);
		_vc_kernel09(b, answ);
		b = _ib[i];
        if(answ[7] != _ib[i]){
                check |= 1;
		} else { check = 0;}
	}

	/* Iterate through _vc_kernel09 64 more times (99 in total)*/
	for (i = 0; i < 64; i++) _vc_kernel09(_ib[31], answ);

	for(i=0;i<8;i++) _ob[i+1] = answ[i];

	/* Mask high nibble of last byte as it's not used */


}


void _vc_kernel07(uint64_t *out, int *oi, const unsigned char in, int offset, int ca)
{
	uint8_t b, c;
  	const uint8_t *key = vc_key;
  	//key = ca == VC_TAC ? vc_key : vc_key;

  	out[*oi] ^= in;
  	b = key[offset + (out[*oi] >> 4)];
  	c = key[offset + (out[*oi] & 0x0F) + 16];
  	c = ~(c + b);
  	c = (c << 1) | (c >> 7);
  	c += in;
  	c = (c << 1) | (c >> 7);
  	c = (c >> 4) | (c << 4);
  	*oi = (*oi + 1) & 7;
  	out[*oi] ^= c;
}



void _vc_rand_seed_sky07(int ca)
{
	int i;
	int oi = 0;
	unsigned char b = 0;
	uint64_t answ[8];
	int offset = 0;

	if(ca == VC_TAC)
	/* TAC key offsets */
	{
		if (_ib[1] > 0x33) offset = 0x08;
		if (_ib[1] > 0x3a) offset = 0x32;
		if (_ib[1] > 0x43) offset = 0x40;
		if (_ib[1] > 0x4a) offset = 0x48;
	}

	else

	/* Sky 07 key offsets */

	{
//		_ib[6] = SKY07_CHID;
		if (_ib[1] > 0x32) offset = 0x08;
  		if (_ib[1] > 0x3a) offset = 0x18;
	}

	/* Reset answers */
	for (i = 0; i < 8; i++)  answ[i] = 0;

	for (i = 0; i < 27; i++) _vc_kernel07(answ, &oi, _ib[i], offset, ca);

	/* Calculate signature */
	for (i = 27; i < 31; i++)
	{
		_vc_kernel07(answ, &oi, b, offset, ca);
		_vc_kernel07(answ, &oi, b, offset, ca);
		b = answ[oi];
		if(answ[oi] != _ib[i]){
                check |= 1;
		} else { check = 0;}
		oi = (oi + 1) & 7;
	}

	/* Iterate through _vc_kernel07 64 more times (99 in total) */
	/* Odd bug(?) in newer TAC card where checksum is always 0x0d */
	for (i = 0; i < 64; i++)
		_vc_kernel07(answ, &oi, (ca == VC_TAC && _ib[1] > 0x30) ? 0x0d : _ib[31], offset, ca);

    for(i=0;i<8;i++){
        _ob[i+1] = answ[i];
    }
}

void _rand_seed_xtea(void)
{
	int i;
	uint32_t v0 = 0;
	uint32_t s0 = 0;
	uint32_t v1 = 0;
	uint32_t s1 = 0;
	uint32_t sum = 0;
	uint32_t delta = 0x9E3779B9;

    /* read input-buffer */
    memcpy(&v1,&_ib[11],4);
    memcpy(&v0,&_ib[15],4);
    memcpy(&s1,&_ib[19],4);
    memcpy(&s0,&_ib[23],4);
    /* XTEA HASH */
	for (i = 0; i < 32;i++)
	{
		v0 += (((v1 << 4)^(v1 >> 5)) + v1)^(sum + xtea_key[sum & 3]);
		sum += delta;
		v1 += (((v0 << 4)^(v0>>5))+v0)^(sum + xtea_key[(sum>>11) & 3]);
        /* SIGNATURE CHECK */
		if(i == 7)
		{
            if((v0 == s0) && (v1 == s1)){
                check = 0;
            }else{
                check = 1;
                break;
            }
		}
	}
	/* copy result to cw-buffer */
    memcpy(&_ob[1],&v1,4);
    memcpy(&_ob[5],&v0,4);

}

void _response(const uint8_t *_data,uint8_t _len){
int a;
enable_tx();
//const uint8_t *data = _data;
uint8_t c = 0;
        for(a = 0;a < _len;a++){
            c = _reverse_byte(pgm_read_byte(&_data[a]));
            io_write( _getParity(c) ? 0x00 | c: 0x100 | c );
            _delay_us(cdelay);
        }
_delay_ms(1);
enable_rx();
}

void _response_cw(uint8_t *_data,uint8_t _len){
enable_tx();
int a;
uint16_t c = 0;
        for(a = 0;a < _len;a++){
            c = _reverse_byte(_data[a]);
            io_write( _getParity(c) ? 0x00 | c: 0x100 | c );
            _delay_us(cdelay);
          }
_delay_ms(1);
enable_rx();
}


void _command(void){
    int i;

    uint8_t ca;

    switch(_ib[1]){
    case 0x0:
        invert = !invert;break;
    case 0x01:
        _response_cw(_ib,_ib[4]);break;
    case 0x78:
        _response_cw(_ob,_ib[4]+1);break;
    case 0x7a:
        // 0 tac / 1 sky / 2 xtea / 3 sky9
        if(check != 0){
            _response(_ans_block,_ib[4]+1);
        } else if(mode == 0 && osdctr < 5){
            osdctr++;
            _response(_ans_tac,_ib[4]+1);
        } else if(mode==1 && osdctr < 5){
            osdctr++;
            _response(_ans_sky,_ib[4]+1);
        } else if(mode==2 && osdctr < 5){
            osdctr++;
            _response(_ans_xtea,_ib[4]+1);
        } else if(mode==3 && osdctr < 5){
            osdctr++;
            _response(_ans_iss09,_ib[4]+1);
        } else {
            _response(_ans_7a,_ib[4]+1);
        }
        //_kupd = 1;
        break;
    case 0x7c:
        _response(_ans_7c,_ib[4]+1);break;
    case 0x74:
		//_delay_us(100);
        io_write(0x100 | _reverse_byte(0x74));
        for(i = 0; i < 32; i++){
            _ib[i] = _reverse_byte(io_read() & 0xff);
        }
        switch(_ib[0]){
        case 0xf8:
            mode = 4;break;
        default:
            switch(_ib[6]){
                case 0x00:
                case 0x20:
                    ca = _ib[6] == 0x00 ? VC_SKY : VC_TAC;
                    mode = ca;
                    _vc_rand_seed_sky07(ca);break;
                case 0x63:
                    mode = 2;
                    _rand_seed_xtea();break;
                case 0x0c:
                    mode = 3;
                    _vc_rand_seed_sky09();break;
                default:
                    break;
            }
        }
    default:
        break;
    }
    _response(_ack,2);

}

int main(void)
{
	uint8_t i;

	io_init();

	/* Enable interrupts */

	//eeprom_read_block(&vc_key[0],&sky09_key[0],216);

	sei();

	enable_rx();

    _response(_atr,16);



	while(1)
	{

        while(_ib[0] != 0x53){
            _ib[0] = _reverse_byte(io_read() & 0xff);
        }

        for(i = 1;i < 5; i++){
            _ib[i] = _reverse_byte(io_read() & 0xff);
        }
        //_delay_ms(1);
        _command();



		if(_kupd > -1){
				switch(mode){
					case 0:
						eeprom_read_block(&vc_key[_kupd * 8],&tac_key[_kupd * 8], 8);break;
					case 1:
						eeprom_read_block(&vc_key[_kupd * 8],&sky07_key[_kupd * 8], 8);break;
					case 3:
						eeprom_read_block(&vc_key[_kupd * 8],&sky09_key[_kupd * 8], 8);break;
					default:
						break;
				}
			_kupd--;
		}

        if(_mode != mode){
            _mode = mode;
            osdctr = 0;
            switch(_mode){
                case 0:
					_kupd = 11;break;
                case 1:
					_kupd = 6;break;
                case 2:
                    for(i=0;i<4;i++)xtea_key[i]=eeprom_read_dword(&_xtea_key[i]);break;
                case 3:
					_kupd = 26;break;
                default:
                    break;
            }
        }

        memset(_ib,0,32);

	}

	return(0);
}
