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

#include "config.h"
#include <avr/io.h>
#include <avr/pgmspace.h>
#include <avr/interrupt.h>
#include "io.h"


/* Serial interface */
static volatile uint16_t _ibuf;
static volatile uint8_t _ibuf_flag;

static volatile uint16_t _obuf;
static volatile uint8_t _obuf_flag;

uint16_t io_read(void)
{
	uint16_t v;

	/* Block until a byte is received */
	while(_ibuf_flag == 0);

	/* Copy the byte and release */
	v = _ibuf;
	_ibuf_flag = 0;

	return(v);
}

void io_write(uint16_t v)
{
	/* Block until the output buffer is empty */
	while(_obuf_flag == 1);

	/* Copy byte and signal interrupt */
	_obuf = v;
	_obuf_flag = 1;
}

void io_init(void)
{
	/* Configure Timer1 (Clear on Compare Match / No Prescaler) */
	TCCR1A = 0;
	TCCR1B = _BV(CTC1) | _BV(CS10); //CTC1 == WGM12 on newer ATMEGA
	OCR1A = F_CPU / 28800.0; //29034.22568620807;
	TIMSK = _BV(OCIE1A); //TIMSK1 on newer ATMEGA

	/* Configure PB6 */
	PORTB &= ~_BV(PORTB6); /* No internal pull-up */
	DDRB &= ~_BV(DDB6);    /* Input */

	/* Clear the serial buffers */
	_ibuf_flag = 0;
	_obuf_flag = 0;
}

ISR(TIMER1_COMPA_vect)
{
	static uint16_t sr = 0x0000;
	static uint8_t state = 0x00;
	static uint8_t b = 0;

	if(state & 0x80)
	{
		/* TX */
		switch(state)
		{
		case 0xA1: /* Next byte */
			state = 0x80;

		case 0x80: /* Init and TX start bit */

			if(_obuf_flag == 0)
			{
				/* No data to send, return to RX */
				state = 0x00;
				break;
			}

			sr = (_obuf << 1) | (1 << 10);
			_obuf_flag = 0;

		case 0x83: /* TX data bits (9-bit) */
		case 0x86:
		case 0x89:
		case 0x8C:
		case 0x8F:
		case 0x92:
		case 0x95:
		case 0x98:
		case 0x9B:
		case 0x9E: /* TX stop bit */

			b = sr & 1;
			sr >>= 1;

		default:
			if(b) DDRB &= ~_BV(DDB6);
			else  DDRB |= _BV(DDB6);

			state++;

			break;
		}
	}
	else
	{
		/* RX */
		b = PINB & _BV(PINB6);

		switch(state)
		{
		case 0x00: /* Waiting for start bit */

			if(_obuf_flag == 1)
			{
				/* A byte is to be transmitted */
				state = 0x80;
				break;
			}

			if((PINB & _BV(PINB6)) == 0)
			{
				/* Input pin is low, clear the shift register
				 * and start receiving bits */
				sr = 0x0000;
				state = 0x01;
			}
			break;

		case 0x1F: /* RX stop bit */

			/* Copy the received byte to the RX buffer */
			if(_ibuf_flag == 0)
			{
				_ibuf = sr;
				_ibuf_flag = 1;
			}

			/* Wait for the next byte */
			state = 0x00;

			break;

		case 0x04: /* RX data bits (9-bit) */
		case 0x07:
		case 0x0A:
		case 0x0D:
		case 0x10:
		case 0x13:
		case 0x16:
		case 0x19:
		case 0x1C:
			sr >>= 1;
			sr |= b ? 1 << 8 : 0;

		default:
			state++;
			break;
		}
	}
}

