#!/usr/bin/env python3.2

import getpass
import imaplib2
import sys
import time

#
# Connection parameters (change these)
#

SERVER   = '<host>[:<port>]'
USERNAME = '<username>'
PASSWORD = getpass.getpass()
USE_SSL  = False
MAILBOX  = 'INBOX'  # Mailbox with at least 6 messages in it

#
# Output configuration
#

_debug_out = True

def msg(msg, *args):
	global _debug_out
	_debug_out and print()
	print('===>', msg.format(*args) if args else msg)
	_debug_out = False

def debug(msg, *args):
	global _debug_out
	_debug_out or print()
	print(msg.format(*args) if args else msg)
	_debug_out = True

# Show raw IMAP data stream
imaplib2.debug_func(debug)
imaplib2.debug_level(4)

#
# IMAP4 connection example
#

# Create a new SSL context if USE_SSL is set to True
ssl_ctx = imaplib2.ssl_context() if USE_SSL else None

msg('Connecting...')

with imaplib2.IMAP4(SERVER, timeout=15, ssl_ctx=ssl_ctx) as imap:
	msg('Server says hi: {}', imap.greeting)

	# Enable TLS if SSL wasn't used and the server supports it
	if not USE_SSL and imaplib2.ssl and 'STARTTLS' in imap.caps:
		msg('Enabling TLS...')
		imap.starttls(imaplib2.ssl_context())

	# Send username and password
	msg('Authenticating...')
	imap.login(USERNAME, PASSWORD)

	# Enable data compression
	if 'COMPRESS=DEFLATE' in imap.caps:
		msg('Enabling compression...')
		imap.compress()
	else:
		msg('Server does not support compression')

	# Check account quota
	if 'QUOTA' in imap.caps:
		msg('Requesting account quota...')
		for resp in imap.getquota(''):
			for name, used, lim in imaplib2.group(resp[-1], 3):
				if name.upper() == 'STORAGE':
					pct = used / lim
					msg('Account quota: {} / {} KB ({:.1%})', used, lim, pct)
					break
	else:
		msg('Server does not support QUOTA extension')

	# List available mailboxes
	msg('Listing all mailboxes...')
	for _, flags, sep, name in imap.list(mbox='*'):
		if name == MAILBOX:
			msg('Found mailbox {!r} ({})', name, ', '.join(flags))
			break
	else:
		msg('Mailbox {!r} not found', MAILBOX)
		sys.exit()

	# Select mailbox and determine the number of available messages
	msg('Selecting mailbox...')
	for resp in imap.select(MAILBOX, readonly=True):
		if resp.dtype == 'EXISTS':
			exists = resp[0]
			msg('The mailbox contains {} messages', exists)
			break

	if exists < 6:
		msg('Please select another mailbox that contains at least 6 messages')
		sys.exit()

	# Concurrent FETCH commands (just an example, '1:6' would be faster)
	msg('Issuing 3 concurrent FETCH commands...')
	cmd1 = imap.fetch((1, 4), 'BODY[HEADER.FIELDS (SUBJECT)]', wait=False)
	cmd2 = imap.fetch((2, 5), 'BODY[HEADER.FIELDS (SUBJECT)]', wait=False)
	cmd3 = imap.fetch((3, 6), 'BODY[HEADER.FIELDS (SUBJECT)]', wait=False)

	# Wait for all commands to finish
	imap.wait_all()

	# Print the subject line of each message
	hdr = lambda hdr: hdr.decode('ascii', 'replace').replace('\r\n', ' ')
	for group in zip(cmd1, cmd2, cmd3):
		for resp in group:
			msg('[Message {}] {}', resp[0], hdr(resp[-1][-1]))
	print()

	# Asynchronous response processing
	msg('Issuing asynchronous FETCH command...')
	cmd = imap.fetch('1:6', 'UID', 'INTERNALDATE', wait=False)
	for seq, _, kv in cmd:
		kv    = dict((k.upper(), v) for k, v in imaplib2.group(kv))
		idate = imaplib2.idate2unix(kv['INTERNALDATE'])
		msg('[Message {}] INTERNALDATE = {}, UID = {}', seq, idate, kv['UID'])

	# Make sure the command was completed without errors
	msg('Command completion: {} {}', cmd.result.status, cmd.result.info)
	cmd.check()

	# IDLE example
	if 'IDLE' in imap.caps:
		msg('Idling for 5 seconds...')
		with imap.idle() as cmd:
			for i in range(5):
				# Could also use imap.block(1)
				time.sleep(1)
				resp = imap.poll()
				msg('Poll: {}', resp if resp else 'Nothing new...')
	else:
		msg('Server does not support IDLE extension')

	msg('Closing connection...')

msg('All done :)')
